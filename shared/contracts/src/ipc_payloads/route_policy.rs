use super::*;

// ── RoutePolicy ────────────────────────────────────────────────────────────

/// Source of a binding write — propagated to the audit trail and
/// stored in the `route_bindings` row alongside the binding itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingSourceDto {
    /// User chose this binding through the GUI directly.
    UserAssigned,
    /// GUI migrated this binding from the legacy `UiPreferences`
    /// fields on first launch after upgrade.
    MigratedFromPreferences,
    /// Service-side recovery write (e.g. previously-bound adapter
    /// disappeared and a fallback was selected).
    Recovery,
}

/// Behavior mode for the (primary, secondary) pair. Slugs match
/// `nrr_shared::RouteBehaviorMode` so wire and storage agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BehaviorModeDto {
    PreferPrimary,
    PreferSecondaryWhenAvailable,
    StrictSecondaryFailClosed,
}

/// One binding row — either primary or secondary slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteBindingDto {
    /// Stable adapter identity (`AdapterName` in `nrr-shared`). Server
    /// validates this against the live `AdapterMonitor` snapshot before
    /// writing.
    pub stable_id: String,
    /// Display name shown in GUI. Cached at write time so the UI does
    /// not need a round-trip to resolve names.
    pub display_name: String,
    /// User explicitly confirmed this role (vs auto-suggested).
    pub user_confirmed: bool,
    /// Earlier ids of this same binding, folded in when the service re-matched
    /// a reinstalled adapter. Read-only: a client holding one of these holds a
    /// stale copy of the current binding, not a different choice.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_stable_ids: Vec<String>,
}

/// Full per-SID policy snapshot. Used as both `RoutePolicyUpdate`
/// response payload and the `route_policy` field of
/// `SnapshotInitialResponse`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RoutePolicyDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<RouteBindingDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary: Option<RouteBindingDto>,
    pub mode: BehaviorModeDto,
    pub block_secondary_when_unavailable: bool,
    /// Kill-switch failure posture. `true` (default) =
    /// fail-closed (block when the secondary can't be resolved); `false` =
    /// fail-open (allow + GUI warning banner). `#[serde(default)]` keeps it
    /// additive — an older service that omits it reads as fail-closed.
    #[serde(default = "kill_switch_fail_closed_default")]
    pub kill_switch_fail_closed: bool,
    /// Which IP protocols the emergency block cuts, as a
    /// bitmask (TCP=1, UDP=2, ICMP=4, IGMP=8, GRE=16, ESP=32, Other=64; all
    /// = 127). `#[serde(default)]` (= all) keeps it additive — an older peer
    /// that omits it reads as "block every protocol".
    #[serde(default = "kill_switch_protocols_default")]
    pub kill_switch_protocols: u16,
    /// When `true`, split-mode fail-closed blocks ALL egress
    /// (catch-all) instead of only cached secondary IPs (see backend). Default
    /// `false` (per-IP). `#[serde(default)]` keeps it additive.
    #[serde(default)]
    pub kill_switch_block_all: bool,
    /// MASTER kill-switch toggle. `false` (default) = OFF,
    /// so NO fail-closed blocking arms at all (full opt-in); the sibling
    /// kill-switch fields are only consulted when this is `true`.
    /// `#[serde(default)]` = `false` keeps it additive.
    #[serde(default)]
    pub kill_switch_enabled: bool,
    /// "Allow name resolution over the primary link while
    /// the kill-switch block-all is engaged". Default `true` — with DNS cut,
    /// an armed block-all is a total blackout and the FQDN cache never
    /// fills; strict users opt out.
    /// `#[serde(default = "default_true")]` keeps it additive.
    #[serde(default = "default_true")]
    pub allow_dns_over_primary: bool,
    /// "Treat a domain as `domain` + `*.domain`". When
    /// `true`, the enforcement layer expands bare-domain rules to also cover
    /// subdomains. Default `true` (the widening only adds coverage towards
    /// the route the rule already names, so it cannot leak to an unintended
    /// route). `#[serde(default = "default_true")]` keeps it
    /// additive — an older peer that omits it reads as the new default, ON.
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
    /// How a SHARED secondary IP is treated. Slug:
    /// `majority-of-ip` (default) | `majority-of-rules` | `any-rule-domain`
    /// (matches `nrr_domain::shared_ip::SharedIpPolicy::as_slug`).
    /// `#[serde(default)]` = balanced default keeps it additive.
    #[serde(default = "shared_ip_policy_default")]
    pub shared_ip_policy: String,
    /// Mode-A un-seeded-IP coverage strategy slug: `per-ip` |
    /// `fail-closed-unknown` (default) | `zone-widening` (matches
    /// `nrr_domain::mode_a_coverage::ModeACoverageStrategy::as_slug`).
    /// `#[serde(default)]` = fail-closed-unknown keeps it additive.
    #[serde(default = "mode_a_coverage_strategy_default")]
    pub mode_a_coverage_strategy: String,
    /// Resolve rule hosts bypassing the OS hosts/adblock file. `true`
    /// (DEFAULT) forces a routable public IP; `false` honours the hosts file.
    /// Defaults to `true` when an older peer omits it (the intended posture).
    #[serde(default = "resolve_hosts_bypass_default")]
    pub resolve_hosts_bypass: bool,
    /// The secondary binding's **link-provider apps**:
    /// executables the user confirmed as establishing/maintaining the
    /// secondary link (VPN client et al.). READ-ONLY here — written through
    /// the dedicated `route.link-provider.set` op, surfaced in this snapshot
    /// DTO so the GUI can display the configured set without a UI-preference
    /// mirror. `#[serde(default)]` (= empty) keeps it additive.
    #[serde(default)]
    pub secondary_link_provider_apps: Vec<LinkProviderAppDto>,
    /// DoH/DoT lockdown MASTER toggle for this SID. `false`
    /// (default) = off. `#[serde(default)]` keeps it additive.
    #[serde(default)]
    pub doh_lockdown_enabled: bool,
    /// When the lockdown applies: `leak-protection-only`
    /// (default) | `always` (matches
    /// `nrr_storage::doh_lockdown::DohLockdownScope::as_slug`).
    #[serde(default = "doh_lockdown_scope_default")]
    pub doh_lockdown_scope: String,
    /// Opt-in AUTOMATIC browser-history seed for this SID:
    /// when `true` the service runs the rule-gated history seed on its own at
    /// boot. `false` (default) = manual button only (privacy-sensitive read —
    /// explicit opt-in). `#[serde(default)]` keeps it additive.
    #[serde(default)]
    pub browser_history_auto_seed: bool,
    /// Kill-switch shared-IP strictness. `false` (default,
    /// "smart"): IPs the shared-IP census has seen on direct (non-rule) hosts
    /// are excluded from the kill-switch per-IP pin/block set (an innocent
    /// co-tenant site is never cut). `true` ("strict"): pin/block every
    /// secondary-destined IP regardless of sharing. `#[serde(default)]`
    /// keeps it additive.
    #[serde(default)]
    pub kill_switch_strict_shared_ips: bool,
    /// What the service may do with the companion domains it
    /// discovers for a routed site (the CDN/media hosts its rules do not
    /// cover). Slug: `off` (do not collect) | `suggest` (default — collect and
    /// offer; apply nothing without confirmation) | `auto` (apply and record in
    /// the user's rules). Matches `nrr_storage::auto_rules::AutoRulesMode::as_slug`.
    /// `#[serde(default = "auto_rules_mode_default")]` keeps it additive — an
    /// older peer that omits it must never read as `off` (silently disabling
    /// discovery) nor as `auto` (silently applying).
    #[serde(default = "auto_rules_mode_default")]
    pub auto_rules_mode: String,
    /// Offer a delivery-shaped companion host (a CDN endpoint) on its
    /// first co-occurrence instead of waiting for the routed site to dominate
    /// that host's traffic across two visits. `false` (default) keeps the wait,
    /// which is what stops a CDN shared with half the internet from being
    /// suggested. Only meaningful while `auto_rules_mode` collects anything.
    /// `#[serde(default)]` keeps it additive — an older peer that omits it must
    /// never read as opted in.
    #[serde(default)]
    pub auto_rules_eager_delivery_names: bool,
    pub binding_source: BindingSourceDto,
    /// May the service check "does this answer on the main link?" on its own?
    /// Defaulted so an older peer reads as "only when asked", which is the
    /// stored default too.
    #[serde(default)]
    pub primary_probe_auto: bool,
    /// Bounds for one such pass. Defaulted to the service's own values so an
    /// omitted key means the same thing everywhere; the service clamps each one
    /// into its allowed range regardless of who sent it.
    #[serde(default = "default_probe_timeout_ms")]
    pub primary_probe_timeout_ms: u32,
    #[serde(default = "default_probe_max_targets")]
    pub primary_probe_max_targets: u32,
    #[serde(default = "default_probe_repeat_secs")]
    pub primary_probe_repeat_secs: u32,
    /// Record the permissive answer for a newly discovered local network
    /// instead of asking about it. Off by default.
    #[serde(default)]
    pub local_networks_auto_accept: bool,
    /// Evaluate a `Zone` rule BEFORE an `ExactIp` one. Off by default: the more
    /// specific address wins, which is what the rule model documents.
    #[serde(default)]
    pub zone_priority_over_ip: bool,
}

/// Additive default for [`RoutePolicyDto::auto_rules_mode`] /
/// [`RoutePolicyUpdateRequest::auto_rules_mode`] — `suggest`. v1 deliberately
/// applies nothing on its own; kept in sync with
/// `nrr_storage::auto_rules::AutoRulesMode::default().as_slug()`.
pub fn auto_rules_mode_default() -> String {
    "suggest".to_string()
}

/// Additive default for [`RoutePolicyDto::doh_lockdown_scope`] /
/// [`RoutePolicyUpdateRequest::doh_lockdown_scope`] — leak-protection-only.
pub fn doh_lockdown_scope_default() -> String {
    "leak-protection-only".to_string()
}

/// One link-provider application of a route binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LinkProviderAppDto {
    /// User-facing Win32 path of the executable (`C:\...\client.exe`).
    pub exe_path: String,
    /// Display name shown in the GUI. May be empty.
    #[serde(default)]
    pub display_name: String,
}

/// `route.link-provider.set` request — replace the caller's link-provider app
/// set for one binding role. Full-replacement semantics: an empty list clears
/// the set ("I don't use a VPN"). `role` defaults to `secondary` (the only
/// role with a provider-app story; more roles may come with more bindings).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteLinkProviderSetRequest {
    #[serde(default = "link_provider_role_default")]
    pub role: String,
    #[serde(default)]
    pub link_provider_apps: Vec<LinkProviderAppDto>,
}

/// Wire default for [`RouteLinkProviderSetRequest::role`].
fn link_provider_role_default() -> String {
    "secondary".to_string()
}

/// `route.link-provider.set` response — the stored set after the write
/// (deduplicated, path-ordered), for GUI confirmation display.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteLinkProviderSetResponse {
    pub role: String,
    pub link_provider_apps: Vec<LinkProviderAppDto>,
}

/// One row of the shared DoH/DoT resolver baseline list.
/// `target_kind` is `ip` | `host`; `target` is the IPv4 literal or hostname.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DohResolverEntryDto {
    /// `ip` or `host` (matches `nrr_storage::doh_lockdown::DohTarget::kind_str`).
    pub target_kind: String,
    /// The IPv4 literal (`8.8.8.8`) or hostname (`dns.google`).
    pub target: String,
    /// Free-text note (provider/country).
    #[serde(default)]
    pub comment: String,
    /// Whether this entry participates in the lockdown (per-row toggle).
    #[serde(default = "doh_entry_enabled_default")]
    pub enabled: bool,
}

/// Wire default for [`DohResolverEntryDto::enabled`] — enabled.
fn doh_entry_enabled_default() -> bool {
    true
}

/// `doh.resolvers.get` response — the full shared resolver baseline list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DohResolversGetResponse {
    pub resolvers: Vec<DohResolverEntryDto>,
}

/// `doh.resolvers.set` request — replace the ENTIRE shared resolver baseline
/// list (full-replacement semantics; an empty list clears it). Privileged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DohResolversSetRequest {
    #[serde(default)]
    pub resolvers: Vec<DohResolverEntryDto>,
}

/// `doh.resolvers.set` response — the stored list after the write.
pub type DohResolversSetResponse = DohResolversGetResponse;

/// `diagnostics.seed-from-browser-history` response. The seed runs asynchronously
/// on a service worker; `started` is `true` when the worker was launched (a
/// browser-history reader is wired), `false` when the feature is unavailable on
/// this build/platform. Per-host counts are logged, not returned (the resolve
/// outlives this reply).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SeedFromBrowserHistoryResponse {
    pub started: bool,
}

/// Wire default for `kill_switch_fail_closed`: fail-closed (`true`). An
/// older peer that omits the field must never silently downgrade an
/// installed fail-closed posture to fail-open on a round-trip.
fn kill_switch_fail_closed_default() -> bool {
    true
}

/// Wire default for `kill_switch_protocols`: `127` (all protocols). An
/// omitting peer must never silently narrow what the emergency block cuts.
fn kill_switch_protocols_default() -> u16 {
    0x7F
}

/// Wire default for `mode_a_coverage_strategy`: `per-ip` — the permissive
/// default installs no catch-all, so default/primary-destined and
/// zone→primary traffic is not blocked; fail-closed-unknown is a paranoid opt-in.
/// Kept in sync with `nrr_domain::mode_a_coverage::ModeACoverageStrategy::default().as_slug()`.
///
/// Public because it is the NORMATIVE spelling of this default: the
/// `UiPreferences` mirror in `nrr-ui-support` and the legacy-preferences
/// migration in the launcher both read it instead of retyping the slug — the
/// three spellings had already drifted apart once.
pub fn mode_a_coverage_strategy_default() -> String {
    "per-ip".to_string()
}

/// Wire default for `resolve_hosts_bypass`: `true` (bypass the hosts file). An
/// omitting peer must read the intended default, not `bool`'s `false`.
fn resolve_hosts_bypass_default() -> bool {
    true
}

/// Request payload for `RoutePolicyUpdate`. Atomically replaces the
/// caller's per-SID policy: send `Some(...)` to bind a slot,
/// `None` to clear it. `binding_source = MigratedFromPreferences` is
/// only valid during the GUI migration flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RoutePolicyUpdateRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<RouteBindingDto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<RouteBindingDto>,
    pub mode: BehaviorModeDto,
    pub block_secondary_when_unavailable: bool,
    /// Kill-switch failure posture (see [`RoutePolicyDto`]).
    /// Defaults to fail-closed when an older GUI omits it.
    #[serde(default = "kill_switch_fail_closed_default")]
    pub kill_switch_fail_closed: bool,
    /// Protocol bitmask the emergency block cuts (see
    /// [`RoutePolicyDto`]). Defaults to all protocols when an older GUI omits it.
    #[serde(default = "kill_switch_protocols_default")]
    pub kill_switch_protocols: u16,
    /// When `true`, split-mode fail-closed blocks ALL egress
    /// (catch-all) instead of only cached secondary IPs (see backend).
    ///
    /// REQUIRED — no wire default. See [`kill_switch_enabled`].
    ///
    /// [`kill_switch_enabled`]: RoutePolicyUpdateRequest::kill_switch_enabled
    pub kill_switch_block_all: bool,
    /// MASTER kill-switch toggle (see [`RoutePolicyDto`]).
    ///
    /// REQUIRED — no wire default, deliberately. This request replaces the
    /// caller's whole per-SID policy, and a field that TURNS PROTECTION OFF
    /// must not be expressible by leaving it out: `#[serde(default)]` on a
    /// `bool` made a message that forgot this field disarm the kill switch
    /// silently. A peer that omits it now gets a malformed-request error, which
    /// is the correct answer for an incomplete full replace — and a loud
    /// failure is strictly better than a quiet disarm.
    ///
    /// Its own subordinate `kill_switch_fail_closed` already had the safe
    /// direction (an explicit `true` default); the master toggle did not.
    pub kill_switch_enabled: bool,
    /// "Allow DNS over the primary link while blocked"
    /// (see [`RoutePolicyDto`]). Defaults to ON when
    /// an older GUI omits it (an armed block-all with DNS cut is a total
    /// blackout).
    #[serde(default = "default_true")]
    pub allow_dns_over_primary: bool,
    /// "Treat a domain as `domain` + `*.domain`" (see
    /// [`RoutePolicyDto`]). Defaults to ON when an older GUI omits it.
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
    /// Shared-IP policy slug (see [`RoutePolicyDto`]).
    /// Defaults to `majority-of-ip` when an older GUI omits it.
    #[serde(default = "shared_ip_policy_default")]
    pub shared_ip_policy: String,
    /// Mode-A un-seeded-IP coverage strategy slug (see [`RoutePolicyDto`]).
    /// Defaults to `fail-closed-unknown` when an older GUI omits it.
    #[serde(default = "mode_a_coverage_strategy_default")]
    pub mode_a_coverage_strategy: String,
    /// Resolve rule hosts bypassing the hosts file (see [`RoutePolicyDto`]).
    /// Defaults to `true` when an older GUI omits it.
    #[serde(default = "resolve_hosts_bypass_default")]
    pub resolve_hosts_bypass: bool,
    /// DoH/DoT lockdown toggle (see [`RoutePolicyDto`]).
    ///
    /// REQUIRED — no wire default. See [`kill_switch_enabled`].
    ///
    /// [`kill_switch_enabled`]: RoutePolicyUpdateRequest::kill_switch_enabled
    pub doh_lockdown_enabled: bool,
    /// DoH/DoT lockdown scope slug (see [`RoutePolicyDto`]).
    /// Defaults to `leak-protection-only` when an older GUI omits it.
    #[serde(default = "doh_lockdown_scope_default")]
    pub doh_lockdown_scope: String,
    /// Opt-in automatic browser-history seed (see
    /// [`RoutePolicyDto`]). Defaults to `false` (off) when an older GUI omits it.
    #[serde(default)]
    pub browser_history_auto_seed: bool,
    /// Kill-switch shared-IP strictness (see [`RoutePolicyDto`]).
    ///
    /// REQUIRED — no wire default. See [`kill_switch_enabled`].
    ///
    /// [`kill_switch_enabled`]: RoutePolicyUpdateRequest::kill_switch_enabled
    pub kill_switch_strict_shared_ips: bool,
    /// Auto-rules mode slug (see [`RoutePolicyDto`]). Defaults to
    /// `suggest` when an older GUI omits it.
    #[serde(default = "auto_rules_mode_default")]
    pub auto_rules_mode: String,
    /// Eager delivery-name suggestions (see [`RoutePolicyDto`]).
    /// Defaults to `false` (wait for the evidence) when an older GUI omits it.
    #[serde(default)]
    pub auto_rules_eager_delivery_names: bool,
    pub binding_source: BindingSourceDto,
    /// May the service check "does this answer on the main link?" on its own?
    /// Defaulted so an older peer reads as "only when asked", which is the
    /// stored default too.
    #[serde(default)]
    pub primary_probe_auto: bool,
    /// Bounds for one such pass. Defaulted to the service's own values so an
    /// omitted key means the same thing everywhere; the service clamps each one
    /// into its allowed range regardless of who sent it.
    #[serde(default = "default_probe_timeout_ms")]
    pub primary_probe_timeout_ms: u32,
    #[serde(default = "default_probe_max_targets")]
    pub primary_probe_max_targets: u32,
    #[serde(default = "default_probe_repeat_secs")]
    pub primary_probe_repeat_secs: u32,
    /// Record the permissive answer for a newly discovered local network
    /// instead of asking about it. Off by default.
    #[serde(default)]
    pub local_networks_auto_accept: bool,
    /// Evaluate a `Zone` rule BEFORE an `ExactIp` one. Off by default: the more
    /// specific address wins, which is what the rule model documents.
    #[serde(default)]
    pub zone_priority_over_ip: bool,
}

impl RoutePolicyUpdateRequest {
    /// Would applying this request move the routing policy away from what
    /// `current` already expresses?
    ///
    /// Clients read-modify-write the whole row, so a save that merely
    /// re-states the stored policy has to stay acceptable even where the
    /// policy itself is frozen — otherwise freezing the policy would freeze
    /// the settings surface around it.
    ///
    /// Provenance and display metadata are deliberately not compared: a
    /// binding's `display_name` / `user_confirmed` and the row's
    /// `binding_source` cannot alter enforcement, and the stored spelling
    /// drifts on its own (adapter identity healing, recovery writes), which
    /// would turn an honest echo into a spurious difference. Adapter identity
    /// (`stable_id`) and whether a slot is bound at all are compared.
    ///
    /// The exhaustive destructuring is load-bearing: a field added to either
    /// struct stops compiling here until someone decides whether it is part of
    /// the policy.
    #[must_use]
    pub fn changes_policy(&self, current: &RoutePolicyDto) -> bool {
        let Self {
            primary,
            secondary,
            mode,
            block_secondary_when_unavailable,
            kill_switch_fail_closed,
            kill_switch_protocols,
            kill_switch_block_all,
            kill_switch_enabled,
            allow_dns_over_primary,
            include_subdomains,
            shared_ip_policy,
            mode_a_coverage_strategy,
            resolve_hosts_bypass,
            doh_lockdown_enabled,
            doh_lockdown_scope,
            browser_history_auto_seed,
            kill_switch_strict_shared_ips,
            auto_rules_mode,
            auto_rules_eager_delivery_names,
            primary_probe_auto,
            primary_probe_timeout_ms,
            primary_probe_max_targets,
            primary_probe_repeat_secs,
            local_networks_auto_accept,
            zone_priority_over_ip,
            binding_source: _,
        } = self;
        let RoutePolicyDto {
            primary: stored_primary,
            secondary: stored_secondary,
            mode: stored_mode,
            block_secondary_when_unavailable: stored_block_secondary,
            kill_switch_fail_closed: stored_fail_closed,
            kill_switch_protocols: stored_protocols,
            kill_switch_block_all: stored_block_all,
            kill_switch_enabled: stored_kill_switch,
            allow_dns_over_primary: stored_dns_over_primary,
            include_subdomains: stored_include_subdomains,
            shared_ip_policy: stored_shared_ip_policy,
            mode_a_coverage_strategy: stored_mode_a_strategy,
            resolve_hosts_bypass: stored_hosts_bypass,
            secondary_link_provider_apps: _,
            doh_lockdown_enabled: stored_doh_enabled,
            doh_lockdown_scope: stored_doh_scope,
            browser_history_auto_seed: stored_history_seed,
            kill_switch_strict_shared_ips: stored_strict_shared_ips,
            auto_rules_mode: stored_auto_rules_mode,
            auto_rules_eager_delivery_names: stored_eager_delivery,
            primary_probe_auto: stored_probe_auto,
            primary_probe_timeout_ms: stored_probe_timeout,
            primary_probe_max_targets: stored_probe_max_targets,
            primary_probe_repeat_secs: stored_probe_repeat,
            local_networks_auto_accept: stored_auto_accept,
            zone_priority_over_ip: stored_zone_priority,
            binding_source: _,
        } = current;

        bound_adapter_id(primary) != bound_adapter_id(stored_primary)
            || bound_adapter_id(secondary) != bound_adapter_id(stored_secondary)
            || mode != stored_mode
            || block_secondary_when_unavailable != stored_block_secondary
            || kill_switch_fail_closed != stored_fail_closed
            || kill_switch_protocols != stored_protocols
            || kill_switch_block_all != stored_block_all
            || kill_switch_enabled != stored_kill_switch
            || allow_dns_over_primary != stored_dns_over_primary
            || include_subdomains != stored_include_subdomains
            || shared_ip_policy != stored_shared_ip_policy
            || mode_a_coverage_strategy != stored_mode_a_strategy
            || resolve_hosts_bypass != stored_hosts_bypass
            || doh_lockdown_enabled != stored_doh_enabled
            || doh_lockdown_scope != stored_doh_scope
            || browser_history_auto_seed != stored_history_seed
            || kill_switch_strict_shared_ips != stored_strict_shared_ips
            || auto_rules_mode != stored_auto_rules_mode
            || auto_rules_eager_delivery_names != stored_eager_delivery
            || primary_probe_auto != stored_probe_auto
            || primary_probe_timeout_ms != stored_probe_timeout
            || primary_probe_max_targets != stored_probe_max_targets
            || primary_probe_repeat_secs != stored_probe_repeat
            // Part of the policy: switching it on makes discovery record
            // permissive answers, which become kill-switch exemptions.
            || local_networks_auto_accept != stored_auto_accept
            || zone_priority_over_ip != stored_zone_priority
    }
}

/// The adapter a slot is bound to, or `None` when the slot is unbound.
fn bound_adapter_id(binding: &Option<RouteBindingDto>) -> Option<&str> {
    binding.as_ref().map(|b| b.stable_id.as_str())
}

/// Response payload — the full new policy snapshot after the write.
/// GUI uses this to update its in-memory cache without re-calling
/// `SnapshotInitial`.
pub type RoutePolicyUpdateResponse = RoutePolicyDto;

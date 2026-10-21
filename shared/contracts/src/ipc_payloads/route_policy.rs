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
}

/// Leak protection. Slugs match `nrr_domain::LeakProtection::as_slug`; an
/// unknown slug is a malformed message, never a fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeakProtectionDto {
    Off,
    /// Offered only with the main-connection default route; the service
    /// refuses it together with `PreferSecondaryWhenAvailable`.
    Sites,
    Everything,
}

impl LeakProtectionDto {
    /// The wire slug, as the clients compare it.
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Sites => "sites",
            Self::Everything => "everything",
        }
    }
}

/// What a caller with no saved policy starts from: the default route the
/// administrator chose at install time, and the leak protection its first save
/// is raised to at least.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FirstPolicyDto {
    pub mode: BehaviorModeDto,
    pub leak_protection_at_least: LeakProtectionDto,
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
    /// Required: a snapshot without it says nothing about protection, and
    /// reading that as `off` would show a protected user as unprotected.
    pub leak_protection: LeakProtectionDto,
    /// Which IP protocols leak protection cuts while it is on, as a
    /// bitmask (TCP=1, UDP=2, ICMP=4, IGMP=8, GRE=16, ESP=32, Other=64; all
    /// = 127). `#[serde(default)]` (= all) keeps it additive — an older peer
    /// that omits it reads as "block every protocol".
    #[serde(default = "kill_switch_protocols_default")]
    pub kill_switch_protocols: u16,
    /// "Allow name resolution over the primary link while everything is
    /// blocked" (`leak_protection = everything`, tunnel down). Default `true`:
    /// with DNS cut the block is a total blackout and the FQDN cache never
    /// fills; strict users opt out.
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
    /// The lockdown decides itself: on while this user has rules for the
    /// additional route, whatever the two fields above say. Default `true`.
    #[serde(default = "default_true")]
    pub doh_lockdown_auto: bool,
    /// Whether the lockdown applies right now, as the service decided it —
    /// read-only, so a client can show "on automatically" without knowing the
    /// rules. Absent from the update request.
    #[serde(default)]
    pub doh_lockdown_effective: bool,
    /// Opt-in AUTOMATIC browser-history seed for this SID:
    /// when `true` the service runs the rule-gated history seed on its own at
    /// boot. `false` (default) = manual button only (privacy-sensitive read —
    /// explicit opt-in). `#[serde(default)]` keeps it additive.
    #[serde(default)]
    pub browser_history_auto_seed: bool,
    /// Shared-IP strictness while leak protection is on. `false` (default,
    /// "smart"): IPs the shared-IP census has seen on direct (non-rule) hosts
    /// are excluded from the per-IP pin/block set (an innocent
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
    /// Complete short names with `short_name_suffix` for a connection that
    /// announces no domain of its own. Off by default.
    #[serde(default)]
    pub short_name_completion: bool,
    /// The network domain the user named; empty when unset.
    #[serde(default)]
    pub short_name_suffix: String,
    /// An application rule takes every address its program uses, even one an
    /// address rule of the other link names. Off by default; an older peer
    /// that omits it reads as off.
    #[serde(default)]
    pub app_rules_take_all_addresses: bool,
    /// What WSL gets while the tunnel is down: `""` (not answered yet;
    /// treated as `as-computer`), `as-computer` or `unprotected`.
    #[serde(default)]
    pub forwarded_outage: String,
    /// Ask a public server for the additional route's external address each
    /// time that route connects. Off by default, and an older peer that omits
    /// it reads as off: the request leaves through the tunnel.
    #[serde(default)]
    pub external_address_auto_check: bool,
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

/// A program named like a VPN client that sits where the user could have put
/// it, so the built-in exemption does not trust it by name: the user is asked
/// to confirm it as the link provider (`route.link-provider.set`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PendingVpnClientDto {
    /// User-facing Win32 path of the executable.
    pub exe_path: String,
    /// Other executables of the same product that sit in a protected install
    /// tree and may be confirmed together with it. Empty when there are none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bundled_exe_paths: Vec<String>,
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
/// `target_kind` is `ip` | `host`; `target` is an address literal or hostname.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DohResolverEntryDto {
    /// `ip` or `host` (matches `nrr_storage::doh_lockdown::DohTarget::kind_str`).
    pub target_kind: String,
    /// An address literal of either family (`198.51.100.8`, `2001:db8::8888`)
    /// or a hostname (`dns.example`).
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
/// on a service worker for the calling user; `started` is `true` when the worker
/// was launched, `false` when it was not. `already-running` says why not when
/// the caller's previous import is still in progress — only one runs per user.
/// Per-host counts are logged, not returned (the resolve outlives this reply).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SeedFromBrowserHistoryResponse {
    pub started: bool,
    #[serde(default)]
    pub already_running: bool,
}

/// Every protocol bit the emergency block knows (TCP=1 … Other=64), and the
/// wire default: an omitting peer must never silently narrow what it cuts.
pub const KILL_SWITCH_PROTOCOLS_ALL: u16 = 0x7F;

fn kill_switch_protocols_default() -> u16 {
    KILL_SWITCH_PROTOCOLS_ALL
}

/// The protocol bits that make the emergency block cut something: TCP/UDP at
/// the connection layer, ICMP/IGMP/GRE/ESP at the packet layer. "Other" (64)
/// is kept on the wire but blocks nothing.
pub const KILL_SWITCH_PROTOCOLS_ENFORCED: u16 = 0x3F;

/// Whether `bits` is a protocol selection the service stores and every mirror
/// keeps. The one answer for all sides. A mask that blocks nothing (`0`, or
/// "Other" alone) is not one: switching leak protection off is
/// `leak_protection = off`'s job, and such a mask is protection that reads as on while
/// blocking nothing. A bit outside the mask is damage, and masking it away
/// would invent a selection.
#[must_use]
pub const fn is_valid_kill_switch_protocols(bits: u16) -> bool {
    bits & KILL_SWITCH_PROTOCOLS_ENFORCED != 0 && bits & !KILL_SWITCH_PROTOCOLS_ALL == 0
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
///
/// A key this build does not know is a malformed request: a peer from another
/// build means something by it, and dropping it while applying the rest would
/// write a policy nobody asked for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RoutePolicyUpdateRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<RouteBindingDto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<RouteBindingDto>,
    pub mode: BehaviorModeDto,
    /// Required: this request replaces the whole policy, so leaving the field
    /// out must be a malformed request, never a quiet switch to `off`.
    /// `sites` with `prefer-secondary-when-available` is refused.
    pub leak_protection: LeakProtectionDto,
    /// Protocol bitmask leak protection cuts (see
    /// [`RoutePolicyDto`]). Defaults to all protocols when an older GUI omits it.
    #[serde(default = "kill_switch_protocols_default")]
    pub kill_switch_protocols: u16,
    /// "Allow DNS over the primary link while blocked"
    /// (see [`RoutePolicyDto`]). Defaults to ON when an older GUI omits it
    /// (a block with DNS cut is a total blackout).
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
    /// Resolve rule hosts bypassing the hosts file (see [`RoutePolicyDto`]).
    /// Defaults to `true` when an older GUI omits it.
    #[serde(default = "resolve_hosts_bypass_default")]
    pub resolve_hosts_bypass: bool,
    /// DoH/DoT lockdown toggle (see [`RoutePolicyDto`]).
    ///
    /// REQUIRED — no wire default. See [`leak_protection`].
    ///
    /// [`leak_protection`]: RoutePolicyUpdateRequest::leak_protection
    pub doh_lockdown_enabled: bool,
    /// DoH/DoT lockdown scope slug (see [`RoutePolicyDto`]).
    /// Defaults to `leak-protection-only` when an older GUI omits it.
    #[serde(default = "doh_lockdown_scope_default")]
    pub doh_lockdown_scope: String,
    /// Let the lockdown decide itself (see [`RoutePolicyDto`]). Defaults to
    /// `true` when an older GUI omits it: the automatic posture is the safe one.
    #[serde(default = "default_true")]
    pub doh_lockdown_auto: bool,
    /// Opt-in automatic browser-history seed (see
    /// [`RoutePolicyDto`]). Defaults to `false` (off) when an older GUI omits it.
    #[serde(default)]
    pub browser_history_auto_seed: bool,
    /// Shared-IP strictness (see [`RoutePolicyDto`]).
    ///
    /// REQUIRED — no wire default. See [`leak_protection`].
    ///
    /// [`leak_protection`]: RoutePolicyUpdateRequest::leak_protection
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
    /// Complete short names with `short_name_suffix` for a connection that
    /// announces no domain of its own. Off by default.
    #[serde(default)]
    pub short_name_completion: bool,
    /// The network domain the user named; empty when unset.
    #[serde(default)]
    pub short_name_suffix: String,
    /// Application rules take all their addresses (see [`RoutePolicyDto`]).
    #[serde(default)]
    pub app_rules_take_all_addresses: bool,
    /// WSL while the tunnel is down (see [`RoutePolicyDto`]).
    #[serde(default)]
    pub forwarded_outage: String,
    /// Automatic external-address check (see [`RoutePolicyDto`]).
    #[serde(default)]
    pub external_address_auto_check: bool,
    /// When not empty, only these fields (wire names) are taken from this
    /// request; the rest stay as stored. Two clients each writing the row they
    /// read lose each other's change; naming what changed keeps both.
    /// `binding-source` always comes from the request: it is this write's
    /// provenance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apply_only: Vec<String>,
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
            leak_protection,
            kill_switch_protocols,
            allow_dns_over_primary,
            include_subdomains,
            shared_ip_policy,
            resolve_hosts_bypass,
            doh_lockdown_enabled,
            doh_lockdown_scope,
            doh_lockdown_auto,
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
            short_name_completion,
            short_name_suffix,
            app_rules_take_all_addresses,
            forwarded_outage,
            external_address_auto_check,
            binding_source: _,
            apply_only: _,
        } = self;
        let RoutePolicyDto {
            primary: stored_primary,
            secondary: stored_secondary,
            mode: stored_mode,
            leak_protection: stored_leak_protection,
            kill_switch_protocols: stored_protocols,
            allow_dns_over_primary: stored_dns_over_primary,
            include_subdomains: stored_include_subdomains,
            shared_ip_policy: stored_shared_ip_policy,
            resolve_hosts_bypass: stored_hosts_bypass,
            secondary_link_provider_apps: _,
            doh_lockdown_enabled: stored_doh_enabled,
            doh_lockdown_scope: stored_doh_scope,
            doh_lockdown_auto: stored_doh_auto,
            // What the service decided, never what the user asked for.
            doh_lockdown_effective: _,
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
            short_name_completion: stored_short_name_completion,
            short_name_suffix: stored_short_name_suffix,
            app_rules_take_all_addresses: stored_app_takeover,
            forwarded_outage: stored_wsl_outage,
            external_address_auto_check: stored_external_check,
            binding_source: _,
        } = current;

        bound_adapter_id(primary) != bound_adapter_id(stored_primary)
            || bound_adapter_id(secondary) != bound_adapter_id(stored_secondary)
            || mode != stored_mode
            || leak_protection != stored_leak_protection
            || kill_switch_protocols != stored_protocols
            || allow_dns_over_primary != stored_dns_over_primary
            || include_subdomains != stored_include_subdomains
            || shared_ip_policy != stored_shared_ip_policy
            || resolve_hosts_bypass != stored_hosts_bypass
            || doh_lockdown_enabled != stored_doh_enabled
            || doh_lockdown_scope != stored_doh_scope
            || doh_lockdown_auto != stored_doh_auto
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
            // Decides which resolvers learn the machine's short names.
            || short_name_completion != stored_short_name_completion
            || short_name_suffix != stored_short_name_suffix
            || app_rules_take_all_addresses != stored_app_takeover
            || forwarded_outage != stored_wsl_outage
            // Sends traffic through the tunnel unasked: a frozen policy holds it.
            || external_address_auto_check != stored_external_check
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

/// Keys [`RoutePolicyDto`] reports that [`RoutePolicyUpdateRequest`] does not
/// accept: written through their own operations, or decided by the service.
pub const ROUTE_POLICY_SNAPSHOT_ONLY_KEYS: [&str; 2] =
    ["secondary-link-provider-apps", "doh-lockdown-effective"];

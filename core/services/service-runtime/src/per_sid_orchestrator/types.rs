//! Domain shapes the orchestrator reads (policy snapshot, active rules) and
//! writes (audit records), plus the orchestrator's own error type.

use super::*;

/// Snapshot of a single user's routing policy as the orchestrator
/// consumes it. Mirrors the wire `RoutePolicyDto` minus the
/// `BindingSource` field (orchestrator does not care how the row got
/// into the DB).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerSidPolicySnapshot {
    pub primary: Option<PerSidBinding>,
    pub secondary: Option<PerSidBinding>,
    pub mode: PerSidBehaviorMode,
    pub block_secondary_when_unavailable: bool,
    /// kill-switch failure posture. `true` = fail-closed
    /// (block when the secondary can't be resolved at apply time); `false` =
    /// fail-open (allow; the GUI warns). Only consulted when
    /// `block_secondary_when_unavailable` is on.
    pub kill_switch_fail_closed: bool,
    /// which IP protocols the emergency block cuts, as the
    /// v16 bitmask (decoded via
    /// [`crate::killswitch_codegen::KillSwitchProtocols::from_bits`]). All =
    /// 127 (default). Only consulted when the kill-switch arms.
    pub kill_switch_protocols: u16,
    /// when `true`, the split-mode
    /// ([`RouteBehaviorMode::PreferPrimary`]) fail-closed block covers ALL
    /// egress (catch-all) instead of only the enumerated secondary destination
    /// IPs, so ICMP/ping and rotating/un-cached IPs of secondary-rule hosts
    /// cannot leak to the primary while the secondary adapter is down. Only consulted in
    /// `PreferPrimary` + fail-closed — the other two modes already catch-all.
    /// Default `false` (per-IP).
    pub kill_switch_block_all: bool,
    /// MASTER kill-switch toggle. `false` (default) = OFF, so
    /// the whole leak-guard is disarmed (full opt-in — any leak while the
    /// secondary is down is then the user's deliberate choice). The
    /// `kill_switch_fail_closed` / `kill_switch_block_all` / `kill_switch_protocols`
    /// fields above are only consulted when this is `true`.
    pub kill_switch_enabled: bool,
    /// OPT-IN "allow name resolution over the primary link while
    /// the kill-switch block-all is engaged". `false` (default) = strict (blocks DNS
    /// too); `true` = add a port-scoped DNS permit so zones keep resolving. Only
    /// consulted in the block-all / secondary-unresolved path.
    pub allow_dns_over_primary: bool,
    /// how a SHARED secondary IP is treated. Drives the
    /// secondary-IP denylist fed to the route/WFP codegen. Default
    /// [`SharedIpPolicy::MajorityOfIp`].
    pub shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy,
    /// kill-switch shared-IP strictness. `false`
    /// (default, "smart"): IPs the shared-IP census has seen on direct
    /// (non-rule) hosts are EXCLUDED from the kill-switch per-IP pin/block set
    /// — blocking a secondary-routed CDN address must not cut an innocent
    /// co-tenant site (e.g. gemini/video-site share Google front-end IPs with
    /// www.search.example; strict pinning killed search.example in every browser).
    /// `true` ("strict"): pin every shared IP regardless of co-tenancy. Routing
    /// (`/32` while the secondary is up) stays governed by `shared_ip_policy`.
    pub kill_switch_strict_shared_ips: bool,
    /// Mode-A (`PreferPrimary`) coverage strategy for a routed domain's
    /// un-seeded edge IP. `FailClosedUnknown` (default) escalates
    /// the per-IP fail-closed to the catch-all so the rotating-IP leak
    /// (e.g. chatgpt over primary) cannot happen; `PerIp` keeps
    /// per-IP-only pinning. Consulted only in `PreferPrimary` + fail-closed.
    pub mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy,
    /// exe paths of the secondary binding's **link-provider
    /// apps** (the VPN client et al. the user confirmed via onboarding —
    /// `route_link_provider_apps` per-SID table). Folded into the kill-switch
    /// `APP_EXEMPT_BASE` permits alongside the built-in `*vpn*` glob
    /// resolutions and the user's primary-app rules, so the app that
    /// establishes the link can always (re)connect under any fail-closed
    /// posture (the C4 self-blocking class). Empty when none configured.
    pub link_provider_exe_paths: Vec<String>,
    /// MASTER DoH/DoT lockdown toggle for this SID.
    /// `false` (default) = off. When on, browser DoH/DoT to the resolver set is
    /// blocked so the observer sees plaintext DNS again.
    pub doh_lockdown_enabled: bool,
    /// when the lockdown applies:
    /// [`DohLockdownScope::LeakProtectionOnly`] (only while the kill-switch master
    /// toggle is on) or [`DohLockdownScope::Always`].
    pub doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope,
    /// the ALREADY-RESOLVED resolver IPv4s to block
    /// (enabled list entries: literal IPs as-is + host entries resolved through
    /// the FQDN cache). The composition root resolves these so the orchestrator
    /// stays mechanism-free. Empty when the lockdown is off or nothing resolved.
    pub doh_resolver_ips: Vec<std::net::Ipv4Addr>,
    ///  — what the service may do with the companion domains it
    /// discovers for a routed site (the CDN/media hosts its rules do not
    /// cover). [`AutoRulesMode::Suggest`] (the default) collects findings and
    /// offers them; nothing is applied without confirmation. Carried on the
    /// snapshot so the discovery pass can read one user's stance without a
    /// second store; the enforcement path does NOT consult it yet.
    pub auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode,
    /// May the service check "does this answer on the main link?" unasked, and
    /// what may one such pass cost. Read here so the probe runner reads one
    /// per-SID source like everything else.
    pub primary_probe_auto: bool,
    pub primary_probe_timeout_ms: u32,
    pub primary_probe_max_targets: u32,
    pub primary_probe_repeat_secs: u32,
    /// Answer for a newly discovered local network without asking. Off by
    /// default; it suppresses the question, never the record.
    pub local_networks_auto_accept: bool,
    /// Evaluate a zone rule ahead of an exact-address rule. Off by default —
    /// the rule model's stated default is that an exact address wins. Read by
    /// the address-ownership arbiter, which is where the two can actually
    /// contest one address.
    pub zone_priority_over_ip: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerSidBinding {
    pub stable_id: String,
    /// User-facing adapter name stored with the binding (e.g.
    /// "swiftvpn VPN OpenVPN Adapter"). Used by the route coordinator to
    /// auto-heal when `stable_id` (a GUID) goes stale after a secondary adapter reinstall —
    /// the friendly name survives the GUID change.
    pub display_name: String,
    pub user_confirmed: bool,
    /// every stable adapter id this binding has been matched
    /// to (current `stable_id` + historical GUIDs the auto-heal folded in). The
    /// coordinator matches a live adapter against ANY of these before falling
    /// back to friendly-name heal, so a secondary adapter whose GUID rotated is recognised
    /// directly. Empty is fine — matching then relies on `stable_id` + name.
    pub known_stable_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerSidBehaviorMode {
    PreferPrimary,
    PreferSecondaryWhenAvailable,
    StrictSecondaryFailClosed,
}

/// Trait the orchestrator uses to read per-SID policy snapshots.
/// Production impl wraps `nrr_storage::RouteBindingsRepository`; tests
/// inject a scripted [`HashMap`].
pub trait RoutePolicySource: Send + Sync {
    fn load_for_sid(&self, sid: &str) -> Option<PerSidPolicySnapshot>;
}

/// Snapshot of the currently-active rules revision plus its
/// behaviour mode. Fed into the WFP codegen on every install /
/// recompile pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveRulesSnapshot {
    pub rule_book: CanonicalRuleBook,
    pub behavior_mode: RouteBehaviorMode,
}

/// Trait the orchestrator uses to read the currently-active rules
/// revision. Production impl wraps `nrr_storage::RevisionsRepository`
/// and the latest `revisions.content_json` decoded via
/// `nrr_domain::rules_json_codec::decode`. Tests inject a scripted
/// snapshot.
///
/// `None` means "no active revision" — orchestrator installs no
/// rule-driven filters for that SID and records `Applied` with
/// `filter_count = 0`. The behaviour-mode catch-all (e.g.
/// `StrictSecondaryFailClosed → Block`) still runs only if rules
/// are available; without rules the orchestrator is effectively
/// pass-through.
pub trait RulesProvider: Send + Sync {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot>;

    /// the active rules for one `principal` (Windows SID).
    /// The default implementation ignores the principal and returns the
    /// global/baseline rules via [`Self::active_rules`], which keeps
    /// scripted/no-op test providers working unchanged. The production
    /// provider overrides this to read the principal's own active revision
    /// with read-through to the baseline (lazy divergence).
    fn active_rules_for(&self, _principal: &str) -> Option<ActiveRulesSnapshot> {
        self.active_rules()
    }
}

/// No-op rules provider — always returns `None`. Useful in test
/// fixtures that exercise the install/remove lifecycle without
/// caring about rules.
#[derive(Default)]
pub struct NoopRulesProvider;

impl RulesProvider for NoopRulesProvider {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        None
    }
}

/// One audited transition in the per-SID apply lifecycle. The caller
/// surfaces these to the audit subsystem; the orchestrator itself does
/// not know about NDJSON or hash chains — it just emits records into a
/// [`PerSidApplyAudit`] sink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerSidApplyAuditRecord {
    pub sid: String,
    pub kind: PerSidApplyAuditKind,
    pub filter_count: u32,
    /// Free-form English message for audit consumption — usually the
    /// `OrchestratorError::Display` output on failure paths or a small
    /// fixed slug on success.
    pub message: String,
}

/// Lifecycle event class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerSidApplyAuditKind {
    /// SID's filter set was newly installed (entered the active set
    /// for the first time, or after a previous `Withdrawn`).
    Applied,
    /// SID was already known and its filter set was replaced
    /// (`recompile_for_sid`, typically driven by `RoutePolicyUpdate`).
    Updated,
    /// SID's filter set was removed (the SID exited the active set).
    Withdrawn,
    /// Install / update / withdraw failed at the WFP layer. The
    /// orchestrator's in-memory state may be inconsistent with the
    /// kernel; production wiring flips `HealthComponent::Apply` to
    /// `Blocking` on this kind.
    Failed,
}

impl PerSidApplyAuditKind {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Applied => "per-sid-policy-applied",
            Self::Updated => "per-sid-policy-updated",
            Self::Withdrawn => "per-sid-policy-withdrawn",
            Self::Failed => "per-sid-policy-failed",
        }
    }
}

/// Sink the orchestrator hands every transition to. Production wiring
/// adapts this to `nrr-diagnostics::AuditWriter`; tests use an
/// in-memory `Vec<PerSidApplyAuditRecord>` collector.
pub trait PerSidApplyAudit: Send + Sync {
    fn emit(&self, record: PerSidApplyAuditRecord);
}

/// No-op sink — useful for `with_noop_*` constructors in unit tests
/// that don't care about audit assertions.
#[derive(Default)]
pub struct NoopPerSidApplyAudit;
impl PerSidApplyAudit for NoopPerSidApplyAudit {
    fn emit(&self, _record: PerSidApplyAuditRecord) {}
}

#[derive(Debug, Clone)]
pub enum OrchestratorError {
    /// SID was empty — caller must filter before calling.
    EmptySid,
    /// the admin baseline principal was passed as a
    /// routing target. The baseline is a per-user DEFAULT resolved via the
    /// provider read-through when a real user's tray connects; it is never
    /// installed as its own machine-wide filter set. A real OS user always
    /// has an `S-…` SID, so this only fires on a programming error.
    BaselineNotRoutable,
    /// WFP plan execution failed. Carries the platform error formatted
    /// for audit/log; structured propagation lands in 16.8.3.4 along
    /// with health/audit wiring.
    WfpFailed(String),
}

impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySid => write!(f, "caller SID is empty"),
            Self::BaselineNotRoutable => {
                write!(f, "baseline principal is not a routable per-SID target")
            }
            Self::WfpFailed(m) => write!(f, "wfp plan failed: {m}"),
        }
    }
}

impl std::error::Error for OrchestratorError {}

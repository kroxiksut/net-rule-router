//! per-SID apply orchestrator.
//!
//! Bridges three subsystems built earlier in 16.8:
//! - [`crate::active_sid_registry::ActiveSidRegistry`] (16.8.3.1) tells
//!   the orchestrator which SIDs currently have a live IPC connection.
//! - `RouteBindingsRepository` carries the per-SID `route_bindings` /
//!   `behavior_mode` / `secondary_block_policy` rows.
//!   The orchestrator reads through a [`RoutePolicySource`] trait so
//!   tests can inject scripted snapshots.
//! - [`nrr_platform_api::wfp::WfpSession`] (extended in 16.8.3.2 to
//!   carry `user_sid` per filter) installs the WFP filters that
//!   actually shape per-user routing.
//!
//! ## Lifecycle
//!
//! On every active-set transition published by `ActiveSidRegistry`:
//! - **SID enters** → `install_for_sid` reads the user's policy
//!   snapshot, generates per-user [`WfpFilterSpec`] entries (each
//!   carrying `user_sid = Some(sid)`), runs them through the WFP
//!   session, and records the installed filter IDs in
//!   [`PerSidFilterSet`].
//! - **SID exits** → `remove_for_sid` looks up the installed filter
//!   IDs, issues `DeleteFilter` actions for each, and drops the entry.
//!
//! When a user's policy changes mid-session (`RoutePolicyUpdate` IPC
//! handler), the orchestrator's [`PerSidApplyOrchestrator::recompile_for_sid`]
//! does a full
//! remove-then-install pass for that SID. Diff-based recompile (only
//! changed filters) is a future optimisation for 16.10+ when the rules
//! schema settles.
//!
//! ## M-1: no user logged in, and the baseline (block 16.19)
//!
//! Enforcement follows **tray presence** (the M-1 routing-presence model):
//! filters exist only for SIDs in the active set. When
//! **nobody is logged in** the active set is empty, so `reconcile`
//! installs nothing and routing is **passthrough** (system default).
//!
//! The admin **baseline** (block 16.19) is a per-user *default*, not a
//! machine-wide floor: it reaches the wire only as a per-user
//! read-through — a real `S-…` SID whose own revision is absent resolves
//! the baseline at install time (`RulesProvider::active_rules_for`). The
//! baseline principal is therefore **never** a routable per-SID target of
//! its own; `install_for_sid` refuses the sentinel
//! ([`OrchestratorError::BaselineNotRoutable`]). Consequence: with no
//! logged-in user there is no baseline enforcement on the wire — by
//! design, so the service never shapes pre-login / system traffic.
//!
//! ## Decision runner — current scope
//!
//! `PerSidDecisionRunner::build_filter_specs` translates a
//! [`PerSidPolicySnapshot`] into a small fixed set of WFP specs that
//! demonstrates the wire-up:
//! - One `Permit` filter at `AleAuthConnectV4` with `user_sid = sid`
//!   for each bound role (primary / secondary).
//!
//! Rules reach enforcement through the codegen path, not through a
//! per-connection engine call: the orchestrator turns the rule book into
//! filter specs. The placeholder set here proves:
//! - filter-set lifecycle (install / remove / replace),
//! - per-SID isolation via `FWPM_CONDITION_ALE_USER_ID`,
//! - audit and registry coordination.
//!
//! ## What is intentionally NOT in 16.8.3.3
//!
//! - Production wiring in `runtime_deps.rs` — comes in 16.8.3.4 along
//!   with audit and multi-user fixture tests.
//! - Decision-engine rule iteration — block 16.10.
//! - Diff-based recompile — performance optimisation; current
//!   implementation is full replace.
//! - WFP filter weight ordering across SIDs — current impl puts every
//!   per-SID filter at the same `BASE_WEIGHT`; production may need a
//!   weight map keyed by (SID, role).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nrr_domain::canonical::CanonicalRuleBook;
use nrr_platform_api::types::{
    WfpAction, WfpFilterAction, WfpFilterId, WfpFilterSpec, WfpLayerKey,
};
use nrr_platform_api::wfp::{FilterFailureMode, WfpSession};
use nrr_shared::RouteBehaviorMode;

use crate::active_sid_registry::ActiveSidRegistry;
use crate::app_observation_lookup::{AppObservationLookup, AppObservationStore};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::killswitch_codegen::{FailClosedExemptions, KillSwitchResolution};
use crate::wfp_codegen::{generate_filters, CodegenInput};

// ── Domain shape ─────────────────────────────────────────────────────────────

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
    /// co-tenant site (0719: gemini/youtube share Google front-end IPs with
    /// www.google.com; strict pinning killed google.com in every browser).
    /// `true` ("strict"): the historic pin-everything behaviour. Routing
    /// (`/32` while the secondary is up) stays governed by `shared_ip_policy`.
    pub kill_switch_strict_shared_ips: bool,
    /// Mode-A (`PreferPrimary`) coverage strategy for a routed domain's
    /// un-seeded edge IP. `FailClosedUnknown` (default since HW-0714) escalates
    /// the per-IP fail-closed to the catch-all so the rotating-IP leak
    ///  chatgpt over primary) cannot happen; `PerIp` keeps the
    /// historic per-IP pinning. Consulted only in `PreferPrimary` + fail-closed.
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
    /// Cut IPv6 while leak protection is on. Free pins IPv4 only, so a host with
    /// an AAAA record otherwise keeps a second, unpinned way out — the same site
    /// travelling the tunnel over v4 and the main link over v6.
    pub block_ipv6_when_protected: bool,
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
    /// "hidemy.name VPN OpenVPN Adapter"). Used by the route coordinator to
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

// ── Active rules provider (block 16.12.A.3) ─────────────────────────────────

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
/// `nrr_domain::rules_json_codec::decode` (block 16.12.A.2). Tests
/// inject a scripted snapshot.
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

// ── Orchestrator state ───────────────────────────────────────────────────────

/// The two switches that decide the SHAPE of a fail-closed set: cut everything
/// or only the enumerated destinations, and whether the IPv6 family goes with
/// it. Grouped because they always travel together.
#[derive(Clone, Copy, Debug)]
struct FailClosedPosture {
    block_all: bool,
    block_ipv6: bool,
}

/// Filters the orchestrator currently has installed for one SID.
#[derive(Clone, Debug, Default)]
pub struct PerSidFilterSet {
    pub sid: String,
    pub installed: Vec<WfpFilterId>,
    /// Destinations the installed set scopes to. Kept so the NEXT install can
    /// name what just came under enforcement — see
    /// [`PerSidApplyOrchestrator::tear_down_flows_to_new_destinations`].
    pub destinations: Vec<std::net::Ipv4Addr>,
    /// Was the additional adapter resolvable when this set was installed?
    /// Read off the LUID-conditional permits the leak-guard emits only once it
    /// has an adapter; the false → true edge is "the tunnel just came up".
    pub secondary_resolved: bool,
}

/// What applying a candidate rule set to one SID would do — derived without
/// installing anything or moving any live state
/// ([`PerSidApplyOrchestrator::preview_for_sid`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SidApplyPreview {
    pub sid: String,
    /// `false` when this SID would enforce nothing at all (no policy row, or no
    /// rules) — the counts below are then zero by definition, not by luck.
    pub enforceable: bool,
    /// Filters the apply would install.
    pub filters: usize,
    /// Filters currently installed for the SID, so a caller can state the
    /// change rather than the destination.
    pub installed_now: usize,
    /// Filters the apply would ADD — an id-level diff against what is installed,
    /// not a total. An identical policy therefore previews as 0/0, which is what
    /// lets a caller distinguish "nothing to do" from "reinstall everything".
    pub additions: usize,
    /// Filters the apply would REMOVE (installed, absent from the new plan).
    pub removals: usize,
    /// Filter ids that appear more than once in the computed set. Non-empty
    /// means the plan would enforce less than it lists.
    pub colliding_filter_ids: Vec<u64>,
    /// App-rule patterns that matched no executable.
    pub unresolved_apps: Vec<String>,
    /// The SID has a secondary binding the OS could not resolve to an adapter.
    pub secondary_binding_unresolved: bool,
}

/// Result of deriving a SID's WFP filter set from its current policy, rules,
/// and FQDN cache (see [`PerSidApplyOrchestrator::compute_filters_for_sid`]).
/// Split out so the initial [`PerSidApplyOrchestrator::install_for_sid`] and
/// the incremental [`PerSidApplyOrchestrator::reconcile_secondary_coverage`]
/// share exactly one filter-derivation path.
/// Why a filter set is being computed.
///
/// The compute is also where the service publishes what the GUI shows about the
/// CURRENT policy — whether the block-all posture is armed, which app rules
/// resolved to no executable, how many shared IPs the kill-switch spared. A
/// preview that wrote those would make the app describe a policy nobody applied,
/// so the intent travels with the call and every publication is gated on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComputeIntent {
    /// The result is about to be installed; live status must follow it.
    Apply,
    /// The result is only being inspected (pre-flight, dry run). Nothing about
    /// the live policy may move.
    Preview,
}

impl ComputeIntent {
    /// `true` when this compute owns the live status the GUI reads.
    const fn publishes(self) -> bool {
        matches!(self, Self::Apply)
    }
}

enum ComputedFilterSet {
    /// The SID installs `filters` (rule-driven Permit/Block + leak-guard),
    /// alongside what the compute learned while deriving them.
    Install(ComputedPlan),
    /// The SID has no per-SID policy row → installs nothing.
    NoPolicy,
    /// The SID has a policy but no active rule revision → installs nothing.
    NoActiveRules,
}

/// What one compute produced: the filter set, plus the facts a caller would
/// otherwise have to re-derive (a pre-flight asks for exactly these).
struct ComputedPlan {
    filters: Vec<WfpFilterSpec>,
    /// App-rule patterns that matched no executable, so their filters were not
    /// built — the rules are stored but enforce nothing.
    unresolved_apps: Vec<String>,
}

// ── Audit (block 16.8.3.4) ───────────────────────────────────────────────────

/// One audited transition in the per-SID apply lifecycle. Block
/// surfaces these to the audit subsystem; the orchestrator
/// itself does not know about NDJSON or hash chains — it just emits
/// records into a [`PerSidApplyAudit`] sink.
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

/// Per-SID apply orchestrator. Owns the `WfpSession` and the in-memory
/// filter-set map; reacts to active-SID set transitions and per-SID
/// policy changes.
/// Source of the current per-filter apply-failure mode. Read fresh on
/// every apply so a mid-session change to the admin's
/// `ApplyFailurePolicy` takes effect on the next reconcile / recompile
/// without re-wiring. Production maps the persisted policy
/// (`AllOrNothing → Strict`, `BestEffort → BestEffort`,
/// `PreFlightThenAllOrNothing → Strict`); tests use a constant.
pub type FilterFailureModeSource = Arc<dyn Fn() -> FilterFailureMode + Send + Sync>;

/// resolves everything the kill-switch
/// needs about a SID's secondary interface (LUID + catch-all exemptions).
/// Read fresh on every apply so a secondary adapter reconnect (new LUID / new server IP)
/// or unplug (`None`) takes effect on the next reconcile / recompile
/// without re-wiring. `None` disables the kill-switch for that apply —
/// failing **open** is the safe default (an egress condition pinned to an
/// unknown interface would never match, turning the paired block into a
/// black hole). Production resolves it through the route coordinator
/// (`kill_switch_exemptions`); tests inject a closure.
pub type KillSwitchResolver = Arc<dyn Fn(&str) -> Option<KillSwitchResolution> + Send + Sync>;

/// resolves the fail-closed exemptions for a SID when the
/// secondary is unresolvable but a fail-closed kill-switch must still arm.
/// Returns the primary's local subnets + any cached VPN-server IPs so a
/// block-all (mode B) does not brick LAN/manageability or trap tunnel
/// reconnection. Defaults to empty; production resolves it through the route
/// coordinator (`fail_closed_exemptions`).
pub type FailClosedExemptionsResolver = Arc<dyn Fn(&str) -> FailClosedExemptions + Send + Sync>;

/// Proactive VPN-client exemption — yields the concrete exe paths
/// of VPN client applications whose role was VERIFIED by a kill-switch drop
/// (see [`crate::vpn_client_registry::LearnedVpnClientApps`]). Read fresh on
/// every compute so a client learned mid-session earns its app-scoped
/// exemption on the very next reconcile. Defaults to empty; production wires
/// the registry via [`PerSidApplyOrchestrator::with_vpn_client_apps_provider`].
pub type VpnClientAppsProvider = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Most rule hosts one apply asks DNS about. A first apply on a large preset
/// can list hundreds; resolving them all at once would be a query burst on
/// behalf of sites the user may never open. The rest are picked up by the
/// ordinary refresh once they are seen.
const UNRESOLVED_HOST_RESOLVE_CAP: usize = 64;

/// Receives the rule hosts an apply could not enforce because no confirmed
/// address exists for them. The implementation resolves them off this thread —
/// an apply must never wait on DNS.
pub type UnresolvedHostsSink = Arc<dyn Fn(Vec<String>) + Send + Sync>;

/// Resolves the fake-IP enforcement context at COMPUTE time, so the WFP plan
/// tracks the live feature state: the toggle, the enforcement mode, and whether
/// the TUN stack is actually running. `None` (or a disabled scope) leaves
/// fake-IP entirely out of the plan. A live read matters in both directions —
/// a plan compiled before the toggle must gain the pool permit on the next
/// compute, and a plan must never suppress/block a host's REAL addresses while
/// the stack is down and applications still receive them from DNS.
pub type FakeIpContextProvider =
    Arc<dyn Fn() -> Option<crate::fake_ip::FakeIpEnforcementContext> + Send + Sync>;

/// "Route before block" ordering hook. Cheap and idempotent: the
/// production impl recomputes the active user's secondary route table. Called
/// from the filter reconcile just before a NEW destination-scoped block is
/// installed, so the destination's route is up first. It must not call back
/// into the orchestrator (the coordinator's route recompute does not).
pub type RouteSyncHook = Arc<dyn Fn() + Send + Sync>;

/// What the shadow comparison found: how many filters each pipeline produced,
/// and whether they describe the same enforcement in the same arbitration order.
///
/// Windows-only, like the comparison itself — off-Windows there is no WFP
/// filter set to compare against.
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct NeutralPlanVerdict {
    live: usize,
    neutral: usize,
    same_set: bool,
    same_order: bool,
    /// A few of the filters each side has and the other does not, rendered for
    /// the log. Bounded: the point is to name the difference, and a set that
    /// diverges wholesale is answered by the counts alone.
    only_live: String,
    only_neutral: String,
}

/// At most this many differing filters are named per side. Enough to identify
/// a category; past it the counts already say the sets diverge wholesale.
#[cfg(windows)]
const NEUTRAL_DIFF_SAMPLE: usize = 4;

/// Render a multiset difference as one short line.
#[cfg(windows)]
fn render_difference(
    entries: &[(nrr_platform_api::wfp_behavioral::BehavioralKey, usize)],
) -> String {
    if entries.is_empty() {
        return String::new();
    }
    let mut parts: Vec<String> = entries
        .iter()
        .take(NEUTRAL_DIFF_SAMPLE)
        .map(|(key, count)| {
            if *count > 1 {
                format!("{key} x{count}")
            } else {
                format!("{key}")
            }
        })
        .collect();
    if entries.len() > NEUTRAL_DIFF_SAMPLE {
        parts.push(format!("(+{} more)", entries.len() - NEUTRAL_DIFF_SAMPLE));
    }
    parts.join("; ")
}

#[cfg(windows)]
impl NeutralPlanVerdict {
    /// Both halves must hold. Same filters in a different arbitration order is
    /// a different policy, not a cosmetic difference: WFP resolves overlapping
    /// filters by weight, so reordering changes which one decides.
    fn agrees(&self) -> bool {
        self.same_set && self.same_order
    }
}

pub struct PerSidApplyOrchestrator {
    /// One lock per SID, held across COMPUTE AND APPLY.
    ///
    /// Deriving a filter set reads the policy, the rules and the live FQDN
    /// cache and takes real time; three things drive it concurrently (the
    /// ~5 s leak-guard tick, the fake-IP replan and the IPC apply trigger).
    /// Without this, a thread that started with an older reading finished last
    /// and reinstalled filters another thread had just taken down - including
    /// a block-all - and the engine ended up holding a set nobody had asked
    /// for. The per-SID state mutex is not enough: it is taken pointwise, so
    /// two computes interleave between its acquisitions.
    apply_locks: Mutex<std::collections::HashMap<String, Arc<Mutex<()>>>>,
    session: Arc<WfpSession>,
    policy_source: Arc<dyn RoutePolicySource>,
    rules_provider: Arc<dyn RulesProvider>,
    fqdn_cache: Arc<dyn FqdnCacheLookup>,
    /// App-routing via observation — observed app→IP map the
    /// codegen reads for `Application` rules. Defaults to an empty in-memory
    /// store (app rules then route nothing) until production wires the live
    /// store fed by the connection observer via [`Self::with_app_observations`].
    app_observations: Arc<dyn AppObservationLookup>,
    /// resolves an `Application` rule's exe name/glob to concrete
    /// on-disk exe paths so the codegen can emit real per-app `ALE_APP_ID`
    /// filters. Defaults to a [`nrr_platform_api::NoopAppPathResolver`]
    /// (app rules then resolve nothing — surfaced as
    /// [`crate::wfp_codegen::CodegenDiagnostic::AppUnresolved`] rather than a
    /// silent apply-skip) until production wires a real resolver via
    /// [`Self::with_app_resolver`].
    app_resolver: Arc<dyn nrr_platform_api::AppPathResolver>,
    audit: Arc<dyn PerSidApplyAudit>,
    failure_mode: FilterFailureModeSource,
    /// resolves the secondary interface LUID +
    /// exemptions the kill-switch needs. Defaults to "unresolved" →
    /// kill-switch off, so the feature is inert until production wires a
    /// real resolver via [`Self::with_kill_switch_resolver`].
    kill_switch_resolver: KillSwitchResolver,
    /// fail-closed exemptions resolver. Used when the
    /// secondary is unresolvable yet the user requested a kill-switch with
    /// the fail-closed posture: mode B then blocks *all* egress except these
    /// exemptions (primary local subnets + any cached VPN-server IPs) so the
    /// box stays manageable and the tunnel can reconnect. Defaults to empty
    /// (loopback/link-local/broadcast are always exempt in the codegen).
    fail_closed_exemptions_resolver: FailClosedExemptionsResolver,
    /// Proactive VPN-client exemption — verified VPN client exe
    /// paths merged into the kill-switch app-exemption set on every compute,
    /// so a known client is permitted through a block-all posture BEFORE its
    /// first drop of the session (rotating provider check IPs defeat the
    /// per-IP reactive exemption). `None` (default) contributes nothing.
    vpn_client_apps_provider: Option<VpnClientAppsProvider>,
    /// Tears down live connections to a destination. Used on the activation
    /// edge so sockets that predate a new rule do not finish on the old link.
    /// `None` leaves the repair to the connection observer's reactive path.
    stale_flow_reset: Option<Arc<dyn nrr_platform_api::fake_ip::stale_flows::StaleFlowReset>>,
    /// Rule hosts this apply could not enforce for lack of a confirmed
    /// address. `None` (default) drops them, which is the pre-existing
    /// behaviour: the host is enforced whenever something else resolves it.
    unresolved_hosts_sink: Option<UnresolvedHostsSink>,
    state: Mutex<HashMap<String, PerSidFilterSet>>,
    /// persists installed filter ids so a
    /// hard-killed prior instance's orphaned filters can be reaped BY ID at the
    /// next start (robust against an unreliable WFP enumerate). `None` disables
    /// persistence (tests / degraded boot).
    ledger: Option<Arc<crate::wfp_filter_ledger::WfpFilterLedger>>,
    /// shared status the codegen's `AppUnresolved`
    /// diagnostics are published into on every filter compute, so the
    /// `SnapshotInitial` handler can surface a GUI banner listing app rules
    /// that resolved to no exe path (and are therefore unenforced). `None`
    /// leaves the diagnostics INFO-logged only (tests / degraded boot).
    app_enforcement_status: Option<crate::app_enforcement_status::AppEnforcementStatus>,
    /// shared count of secondary IPs the "smart"
    /// kill-switch excluded this compute (census-shared with direct hosts).
    /// Written on every filter compute; read by `SnapshotInitial` for the GUI
    /// warning. `None` (default) = log-only.
    shared_ip_exemption_status: Option<crate::app_enforcement_status::SharedIpExemptionStatus>,
    /// OS resolver-cache flush, fired on the
    /// fail-closed block-all arming/disarming EDGE (see
    /// [`Self::note_block_all_state`]). Names resolved before the block armed
    /// sit in the OS resolver cache, so the DNS observer never sees them and
    /// their suffix/zone permits are never built (0717 HW: `ya.ru` under
    /// `zone ru → primary` stayed blocked — it was answered from the OS cache
    /// and therefore absent from the FQDN cache). Defaults to
    /// [`nrr_platform_api::NoopDnsCacheControl`]; production wires the real
    /// per-OS mechanism via [`Self::with_dns_cache_control`].
    dns_cache_control: Arc<dyn nrr_platform_api::DnsCacheControlPort>,
    /// Per-SID latch behind the arming-edge detection for the flush above.
    /// `true` = the last compute for this SID produced a fail-closed
    /// block-all set. Only transitions trigger a flush — the leak-guard
    /// reconcile recomputes every few seconds and must not flush steadily.
    block_all_flush_state: Mutex<HashMap<String, bool>>,
    /// Per SID, the highest standing filter volume already reported above the
    /// alarm line. The reconcile recomputes every few seconds, so the watchdog
    /// speaks only on a NEW peak — a plain rising edge went quiet after the
    /// first crossing and had nothing to say about the six hours that followed.
    /// Alarm, never self-healing: unpinning a guard would trade the BFE crash
    /// for a leak.
    standing_volume_alarmed: Mutex<std::collections::HashMap<String, usize>>,
    /// Who is asking for a cut the packet layer cannot scope to one user.
    /// The WFP packet layers carry no `ALE_USER_ID`, so one principal's
    /// block-all (or IPv6 cut) takes ICMP and IPv6 away from everyone logged
    /// in. The others are told rather than left to discover it.
    machine_wide_cut_state: Mutex<HashMap<String, bool>>,
    /// Last reported set of rules this SID names on BOTH routes, as a
    /// fingerprint. The state persists until the user resolves it, so the
    /// notice fires on a CHANGE — repeating it on every apply would teach them
    /// to dismiss it unread.
    cross_set_duplicate_state: Mutex<HashMap<String, String>>,
    /// App-match patterns already announced to this SID. A rule is only news
    /// the first time it is delivered; every later apply carries it again.
    announced_app_rules: Mutex<HashMap<String, std::collections::BTreeSet<String>>>,
    /// Push bus for those notices. `None` in tests that do not care.
    events: Option<Arc<crate::ipc_handlers::event_bus::EventBus>>,
    /// last LOGGED kill-switch posture per SID. The
    /// leak-guard reconcile recomputes every ~5 s, and repeating the armed /
    /// fail-closed posture line each tick flooded the operational NDJSON
    /// (hundreds of identical warns per run — they alone would exhaust the
    /// 5 MiB diagnostic-archive log cap). Posture logs fire at full level on
    /// a CHANGE (see [`PostureLogEvent::Transition`]) and, for callers that
    /// opt in, on a periodic heartbeat while the posture persists (see
    /// [`PostureLogEvent::Heartbeat`]); steady-state re-derivations between
    /// those fire at `debug`.
    posture_log_state: Mutex<HashMap<String, PostureLogLatch>>,
    /// When the provider yields a context whose scope is enabled, the codegen is
    /// augmented: the fake pool is permitted, and the real IPs a fake-routed host
    /// shares with a directly-routed one lose their `/32` permit (fed into the
    /// secondary denylist). Resolved fresh on EVERY compute (see
    /// [`FakeIpContextProvider`]); the default provider yields `None`, leaving
    /// fake-IP out of the plan. Production wires this via
    /// [`Self::with_fake_ip_context_provider`] from the fake-IP setting, the
    /// enforcement mode, and the live stack state.
    fake_ip_context: FakeIpContextProvider,
    /// session registry of destinations positively
    /// established as DIRECT (non-rule) hosts: a Mode-B steered direct answer,
    /// or an FCrDNS forward-confirmed non-rule name. Under the catch-all
    /// block-all each earns an ALE exempt + packet permit (minus anything
    /// secondary-destined) so plain primary-path sites survive the posture.
    /// `None` (default) keeps the strict block-all.
    known_direct: Option<Arc<crate::known_direct::KnownDirectRegistry>>,
    /// shared "block-all armed" posture for the GUI banner
    /// (see [`crate::app_enforcement_status::BlockAllPostureStatus`]). Written
    /// on every block-all transition edge. `None` (default) = log-only.
    block_all_posture_status: Option<crate::app_enforcement_status::BlockAllPostureStatus>,
    /// Per-SID latch for the WIDER "the additional link is unresolved and the
    /// guard is blocking" posture — armed for the per-IP block set too, not
    /// just the catch-all. Feeds
    /// [`crate::app_enforcement_status::FailClosedPostureStatus`], which the
    /// DNS handler and the hostname seeder read: while it is armed the guard
    /// can only block addresses it already knows, so neither of them may act as
    /// if a rule host were covered.
    fail_closed_state: Mutex<HashMap<String, bool>>,
    /// Shared publication of the latch above. `None` (default) = log-only.
    fail_closed_posture_status: Option<crate::app_enforcement_status::FailClosedPostureStatus>,
    /// Reactive VPN-endpoint learning — publishes the WFP spec ids of the
    /// CURRENT kill-switch/fail-closed BLOCK filters so the connection
    /// observer's learner can role-verify a drop before trusting it (see
    /// [`crate::killswitch_drop_registry::KillswitchBlockFilterRegistry`]).
    /// `None` (default) leaves the registry unpublished — the consumer-side
    /// gate then stays permanently closed.
    killswitch_drop_registry:
        Option<Arc<crate::killswitch_drop_registry::KillswitchBlockFilterRegistry>>,
    /// Per-SID bookkeeping behind [`Self::killswitch_drop_registry`]: each
    /// compute publishes only the SID it just derived, but the registry's
    /// `publish` replaces its ENTIRE set — so this tracks every SID's most
    /// recent kill-switch/fail-closed Block id set and the registry is always
    /// republished with their union, or a concurrently-active second SID's
    /// filters would be evicted the moment the first SID's next reconcile runs.
    killswitch_block_ids_by_sid: Mutex<HashMap<String, KillswitchBlockIds>>,
    ///  — "route before block" ordering hook. Invoked, off every
    /// lock, immediately BEFORE a reconcile installs a DESTINATION-scoped
    /// BLOCK it was not already tracking. The production impl recomputes the
    /// active user's secondary route table, so the freshly-pinned destination
    /// has its `/32` in place before the block that only tolerates traffic
    /// egressing the secondary goes up — otherwise the destination is dropped
    /// for as long as the two passes disagree (they read the same live FQDN /
    /// app-observation stores but at different instants, so a concurrent
    /// recompute could pin an address whose route pass had already run).
    /// `None` (default) keeps the historical ordering.
    route_sync: Option<RouteSyncHook>,
    /// Queue drained by the resume watchdog. A fail-closed posture that persists
    /// past a heartbeat asks here for a fresh binding resolution — the machine
    /// may have woken into a network where the bound tunnel adapter is gone.
    rebind_requests: Option<Arc<crate::power_resume::RebindRequests>>,
}

/// Outcome of the posture rate-limiter for one log call: whether it should
/// log at full level because the posture just changed, at full level again
/// because the (unchanged) posture has persisted long enough to earn a
/// heartbeat, or be suppressed to `debug` as steady-state repetition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostureLogEvent {
    /// The posture differs from the last one latched for this SID (or
    /// nothing was latched yet).
    Transition,
    /// The posture is unchanged, but at least the heartbeat interval has
    /// elapsed since the last full-level line for it. Carries the time
    /// since the posture was first entered.
    Heartbeat { elapsed: Duration },
    /// The posture is unchanged and the heartbeat interval has not yet
    /// elapsed.
    Steady,
}

/// Latch recorded per SID behind the posture rate-limiter: which posture is
/// current, when it was entered, and when it last logged at full level.
#[derive(Debug, Clone, Copy)]
struct PostureLogLatch {
    posture: &'static str,
    entered_at: Instant,
    last_logged_at: Instant,
}

/// How often an unchanged, persisting posture re-announces itself at full
/// level (see [`PostureLogEvent::Heartbeat`]). A long block-all session that
/// never changes state would otherwise go from two WARN lines straight to
/// silence for its entire duration — this keeps a periodic "still here"
/// trail without flooding steady-state ticks.
const POSTURE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Pure decision core behind the posture rate-limiter: given the latch
/// previously recorded for a SID (if any), the posture this compute just
/// derived, and the current time, decide whether this call is a state
/// transition, a periodic heartbeat, or steady-state repetition — and the
/// latch to store afterwards. Free of locks/HashMaps so it is unit-testable
/// without a live orchestrator or a real clock (callers can synthesize
/// future `Instant`s via `Instant::now() + Duration::from_secs(n)`).
fn evaluate_posture_log(
    prior: Option<PostureLogLatch>,
    posture: &'static str,
    now: Instant,
    heartbeat_interval: Duration,
) -> (PostureLogEvent, PostureLogLatch) {
    if let Some(latch) = prior {
        if latch.posture == posture {
            return if now.duration_since(latch.last_logged_at) >= heartbeat_interval {
                (
                    PostureLogEvent::Heartbeat {
                        elapsed: now.duration_since(latch.entered_at),
                    },
                    PostureLogLatch {
                        last_logged_at: now,
                        ..latch
                    },
                )
            } else {
                (PostureLogEvent::Steady, latch)
            };
        }
    }
    (
        PostureLogEvent::Transition,
        PostureLogLatch {
            posture,
            entered_at: now,
            last_logged_at: now,
        },
    )
}

/// One compute's BLOCK ids, split by blocking scope — see
/// [`crate::killswitch_drop_registry`] for why the drop detector must keep the
/// bands apart.
type KillswitchBlockIds = crate::killswitch_drop_registry::ScopedBlockIds;

/// Fold every BLOCK-action spec's id into `into` — the accumulator behind the
/// reactive VPN-endpoint learner's role-verification registry (see
/// [`PerSidApplyOrchestrator::update_killswitch_registry`]). Permit filters in
/// the same batch (e.g. the kill-switch's own egress-conditional permit half)
/// never qualify — only a BLOCK can be the filter that produced a drop.
/// App-only blocks are additionally recorded as app-scoped.
///
/// Blocks at a V6 layer are the blanket IPv6 cut and go to `ipv6_cut` INSTEAD:
/// role verification exists to prove something about the tunnel, and every
/// consumer of that proof is IPv4-only. Keeping them out also lets the notice
/// path name the real cause instead of blaming a rule.
fn collect_block_ids(specs: &[WfpFilterSpec], into: &mut KillswitchBlockIds) {
    for spec in specs.iter().filter(|s| s.action == WfpAction::Block) {
        if matches!(
            spec.layer,
            WfpLayerKey::AleAuthConnectV6 | WfpLayerKey::OutboundIpPacketV6
        ) {
            into.ipv6_cut.insert(spec.id.raw);
            continue;
        }
        into.all.insert(spec.id.raw);
        if is_app_only_block(spec) {
            into.app_scoped.insert(spec.id.raw);
        }
    }
}

/// True when `spec` is a BLOCK carrying a destination condition — a remote
/// address or subnet. The companion egress-conditional permit of such a block
/// becomes satisfiable as soon as that destination's secondary route exists,
/// which is why installing one must never precede the route (see
/// [`PerSidApplyOrchestrator::with_route_sync`]).
fn is_destination_block(spec: &WfpFilterSpec) -> bool {
    spec.action == WfpAction::Block
        && (spec.remote_ip.is_some()
            || !spec.remote_ip_set.is_empty()
            || spec.remote_subnet.is_some()
            || spec.remote_subnet_v6.is_some())
}

/// True when `spec` is a BLOCK that scopes to an application only (an ALE
/// app-id condition) and matches no destination — no remote IP, no remote
/// subnet (v4 or v6), so it is not a catch-all either. Skipping such a block
/// (e.g. its exe did not resolve) cannot uncover a destination, so it must NOT
/// arm the reconcile deferral gate (HW-0718 — a persistently-absent exe
/// otherwise deferred the superseded-permit delete pass forever).
fn is_app_only_block(spec: &WfpFilterSpec) -> bool {
    spec.action == WfpAction::Block
        && spec.app_pattern.is_some()
        && spec.remote_ip.is_none()
        && spec.remote_ip_set.is_empty()
        && spec.remote_subnet.is_none()
        && spec.remote_subnet_v6.is_none()
}

/// Whether `ip` sits in any of `subnets`, given as `(network, prefix_len)`.
fn in_any_subnet(ip: std::net::Ipv4Addr, subnets: &[(std::net::Ipv4Addr, u8)]) -> bool {
    let addr = u32::from(ip);
    subnets.iter().any(|(net, prefix)| {
        if *prefix == 0 {
            return true;
        }
        if *prefix > 32 {
            return false;
        }
        let mask = u32::MAX << (32 - u32::from(*prefix));
        (addr & mask) == (u32::from(*net) & mask)
    })
}

impl PerSidApplyOrchestrator {
    /// Record whether the latest compute for `sid` produced a fail-closed
    /// block-all set and flush the OS resolver cache on the transition
    /// EDGE (both directions):
    ///
    /// - disarmed → armed: everything the user resolved *before* the block
    ///   must re-query on the wire so the DNS observer sees it and the next
    ///   reconcile builds its permit (otherwise a `zone → primary` host the
    ///   OS already cached stays blocked with no diagnostic trail);
    /// - armed → disarmed: negative/blocked-era entries must not linger.
    ///
    /// Steady states never flush — the leak-guard reconcile recomputes every
    /// few seconds and a per-tick flush would defeat the OS cache entirely.
    fn note_block_all_state(&self, sid: &str, armed: bool) {
        let transitioned = {
            let mut g = self
                .block_all_flush_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let prior = g.get(sid).copied().unwrap_or(false);
            if prior != armed {
                g.insert(sid.to_string(), armed);
                true
            } else {
                false
            }
        };
        if !transitioned {
            return;
        }
        // publish the new "any SID armed?" posture for the GUI
        // banner. On the transition edge only (same throttle as the flush).
        if let Some(status) = self.block_all_posture_status.as_ref() {
            status.set(self.any_block_all_armed());
        }
        match self.dns_cache_control.flush_resolver_cache() {
            Ok(()) => tracing::info!(
                target: "nrr::per_sid_orchestrator",
                sid,
                block_all_armed = armed,
                "flushed OS DNS resolver cache on kill-switch block-all transition — pre-transition cached names will re-query and become observable",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                sid,
                block_all_armed = armed,
                error = ?e,
                "OS DNS resolver cache flush failed on kill-switch block-all transition — names the OS already cached stay invisible to the DNS observer until their TTL expires",
            ),
        }
    }

    /// Record whether the latest compute for `sid` left the guard BLOCKING with
    /// the additional link unresolved, and publish the "any SID armed?" answer
    /// on the transition edge.
    ///
    /// No cache flush and no logging of its own: the posture it mirrors is
    /// already logged where it is decided, and this latch exists for readers
    /// that must not treat a rule host as covered while the guard has nothing
    /// but its known addresses to block with.
    fn note_fail_closed_state(&self, sid: &str, armed: bool) {
        let transitioned = {
            let mut g = self
                .fail_closed_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let prior = g.get(sid).copied().unwrap_or(false);
            if prior != armed {
                g.insert(sid.to_string(), armed);
                true
            } else {
                false
            }
        };
        if !transitioned {
            return;
        }
        if let Some(status) = self.fail_closed_posture_status.as_ref() {
            status.set(self.any_fail_closed_armed());
        }
    }

    /// Drop every per-SID record describing an enforcement that is gone: the
    /// installed-filter set, both posture latches, the kill-switch block-id
    /// registry and the posture-log throttle (so a later re-arm logs as the
    /// transition it is, not as a steady state).
    fn forget_sid_state(&self, sid: &str) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        crate::enforced_addresses::global_enforced_addresses().forget(sid);
        self.note_block_all_state(sid, false);
        self.note_fail_closed_state(sid, false);
        self.update_killswitch_registry(sid, KillswitchBlockIds::default());
        self.posture_log_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
    }

    /// Tell everyone else when somebody arms a cut that reaches them.
    ///
    /// Published on the CHANGE only, and only to principals whose own plan asks
    /// for no such cut: a notice repeated on every recompute is one the user
    /// learns to dismiss without reading. The Linux side does the same from
    /// `PrincipalEnforcementCycle` — same event, same slug, because the
    /// limitation is the packet layer's on both systems, not this backend's.
    fn note_machine_wide_cut(&self, sid: &str, wants: bool) {
        let (changed, bystanders) = {
            let mut g = self
                .machine_wide_cut_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let prior = g.insert(sid.to_string(), wants);
            let changed = prior != Some(wants);
            let anybody_cuts = g.values().any(|v| *v);
            let bystanders: Vec<String> = if anybody_cuts {
                g.iter()
                    .filter(|(_, cuts)| !**cuts)
                    .map(|(other, _)| other.clone())
                    .collect()
            } else {
                Vec::new()
            };
            (changed, bystanders)
        };
        if !changed || bystanders.is_empty() {
            return;
        }
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        for other in bystanders {
            bus.publish_for(
                other,
                nrr_shared::ipc_payloads::StatusUpdateEvent::ProtectionCoverageChanged {
                    reason: "machine-wide-cut-by-another-user".to_string(),
                },
            );
        }
    }

    /// Tell the user when an application rule is delivered for the first time.
    ///
    /// Its route exists only for addresses the service has already seen the
    /// program use, so the first contact with each new one is refused while it
    /// is learnt. A program that gives up on that refusal looks broken until it
    /// is restarted, and nothing on screen would explain why.
    fn note_new_app_rules(&self, sid: &str, secondary_apps: &[String]) {
        let current: std::collections::BTreeSet<String> = secondary_apps.iter().cloned().collect();
        let fresh: Vec<String> = {
            let mut announced = self
                .announced_app_rules
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let known = announced.entry(sid.to_string()).or_default();
            let fresh: Vec<String> = current.difference(known).cloned().collect();
            // Replaced wholesale: a rule the user removed and adds again is news
            // for the same reason it was the first time.
            *known = current;
            fresh
        };
        if fresh.is_empty() {
            return;
        }
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            sid,
            apps = %fresh.join(", "),
            "application rules delivered for the first time — their destinations are still being learnt",
        );
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                sid,
                nrr_shared::ipc_payloads::StatusUpdateEvent::AppRuleLearningDestinations {
                    sid: sid.to_string(),
                    apps: fresh,
                },
            );
        }
    }

    /// Say when this SID's active rules name the same traffic on both routes
    /// with both copies enabled.
    ///
    /// Nothing in the running policy shows this: the rules are valid, they
    /// simply disagree about where the traffic goes, and evaluation order
    /// settles it instead of the user. Reported on apply and only when the set
    /// changes — the condition lasts until they resolve it.
    fn note_cross_set_duplicates(
        &self,
        sid: &str,
        book: &nrr_domain::canonical::CanonicalRuleBook,
    ) {
        let found = nrr_domain::validation::enabled_duplicates_across_sets(book);
        let fingerprint = found
            .iter()
            .map(|pair| pair.match_summary.as_str())
            .collect::<Vec<_>>()
            .join("|");
        {
            let mut seen = self
                .cross_set_duplicate_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if seen.get(sid).map(String::as_str) == Some(fingerprint.as_str()) {
                return;
            }
            seen.insert(sid.to_string(), fingerprint);
        }
        let Some(first) = found.first() else {
            return; // resolved — nothing to announce, the state was recorded
        };
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            sid,
            count = found.len(),
            sample = %first.match_summary,
            "active rules name the same traffic on both routes",
        );
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                sid,
                nrr_shared::ipc_payloads::StatusUpdateEvent::RuleDuplicatesDetected {
                    sid: sid.to_string(),
                    count: found.len() as u64,
                    sample: first.match_summary.clone(),
                },
            );
        }
    }

    /// Build the fail-closed filter set for the failure posture. Mode A
    /// (selective) blocks only the protected secondary destinations; modes B
    /// (everything-via-secondary) block all egress except the safe
    /// exemptions. Pure projection over the codegen primitives.
    fn fail_closed_filters(
        &self,
        sid: &str,
        mode: RouteBehaviorMode,
        protected_secondary_ips: &[Ipv4Addr],
        exemptions: &FailClosedExemptions,
        protocols: crate::killswitch_codegen::KillSwitchProtocols,
        posture: FailClosedPosture,
    ) -> Vec<WfpFilterSpec> {
        let FailClosedPosture {
            block_all,
            block_ipv6,
        } = posture;
        match mode {
            RouteBehaviorMode::PreferPrimary => {
                // with `kill_switch_block_all` the split-mode
                // emergency block covers ALL egress (catch-all) so ICMP/ping and
                // rotating/un-cached secondary-rule IPs can't leak to the primary
                // while the secondary adapter is down; otherwise it blocks only the enumerated
                // secondary destinations (the historic per-IP behaviour).
                if block_all {
                    crate::killswitch_codegen::fail_closed_block_all_filters(
                        sid, exemptions, protocols,
                    )
                } else {
                    // honour the VPN-server (bootstrap) exemption on
                    // the mode-A per-IP path too: subtract the exempted server IPs
                    // from the per-destination block set so, if a secondary rule
                    // ever resolved to the tunnel's own server IP, the handshake to
                    // it is never blocked. Mirrors the block-all path, which already
                    // exempts bootstrap_server_ips. (The per-app primary exemption
                    // above is the primary deadlock fix; this closes the IP-overlap
                    // corner case as defence-in-depth.)
                    let protected: Vec<Ipv4Addr> = protected_secondary_ips
                        .iter()
                        .copied()
                        .filter(|ip| !exemptions.bootstrap_server_ips.contains(ip))
                        .collect();
                    let mut out = crate::killswitch_codegen::fail_closed_block_destinations(
                        sid, &protected, protocols,
                    );
                    // The per-IP path is the ONE posture that used to leave IPv6
                    // wide open: the family is cut while the tunnel is up and was
                    // un-cut the moment it dropped, so a host whose v4 we had just
                    // blocked stayed reachable over its AAAA — exactly when the
                    // guard was supposed to be strictest. The block-all branches
                    // carry the cut already.
                    if block_ipv6 {
                        out.extend(crate::killswitch_codegen::catch_all_v6_filters(
                            sid,
                            exemptions.secondary_luid,
                        ));
                    }
                    out
                }
            }
            RouteBehaviorMode::PreferSecondaryWhenAvailable
            | RouteBehaviorMode::StrictSecondaryFailClosed => {
                // `block_all` is honoured here too. It used to be ignored, and
                // the caller that arms the guard while the tunnel is HEALTHY
                // (empty pin set on a cold FQDN cache) states in its own
                // comment that it must not escalate — it passed `false` and got
                // a catch-all anyway, cutting every egress on a live tunnel and
                // deadlocking the very cache warm-up that would lift it.
                if block_all {
                    crate::killswitch_codegen::fail_closed_block_all_filters(
                        sid, exemptions, protocols,
                    )
                } else {
                    let protected: Vec<Ipv4Addr> = protected_secondary_ips
                        .iter()
                        .copied()
                        .filter(|ip| !exemptions.bootstrap_server_ips.contains(ip))
                        .collect();
                    let mut out = crate::killswitch_codegen::fail_closed_block_destinations(
                        sid, &protected, protocols,
                    );
                    if block_ipv6 {
                        out.extend(crate::killswitch_codegen::catch_all_v6_filters(
                            sid,
                            exemptions.secondary_luid,
                        ));
                    }
                    out
                }
            }
        }
    }

    /// Derive the full WFP filter set for `sid` from its current policy, rules,
    /// and the (live) FQDN cache — including the leak-guard kill-switch — WITHOUT
    /// touching the WFP engine or the in-memory installed-set. Split out of
    /// [`Self::install_for_sid`] so the incremental
    /// [`Self::reconcile_secondary_coverage`] shares exactly one filter-
    /// derivation path. Because the FQDN cache is read live, calling it again
    /// after the DNS observer warms the cache yields the freshly-resolved
    /// secondary destinations (block 16.HW-0704 P1), and re-resolving the LUID
    /// yields the current tunnel after a reconnect (gap #2).
    /// reset the shared unresolved-app set to
    /// empty so the GUI banner does not keep listing apps for a SID that no
    /// longer has any (enforceable) rules. No-op when the status is unwired.
    fn clear_app_enforcement_status(&self) {
        if let Some(status) = self.app_enforcement_status.as_ref() {
            status.set_unresolved(Vec::new());
        }
    }

    /// Run the neutral pipeline alongside the live one and report whether they
    /// agree. Compares only — nothing here reaches the kernel.
    ///
    /// This is the evidence step of moving enforcement onto the neutral plan.
    /// The equivalence is already proven by oracle tests over hand-built rule
    /// books; what those cannot cover is the shape of a real user's rules, with
    /// its own cache contents, app resolutions and fan-outs. So the two run
    /// side by side on live input first, and only a silent log promotes the
    /// neutral one to the path that enforces.
    ///
    /// Deliberately narrow: rule-driven flows only, and only what the planner
    /// models today. The fake-IP augmentation is folded in by the caller AFTER
    /// this returns, and the kill-switch classes are compared by their own
    /// oracle tests — widening this to them before they are modelled would
    /// report a difference that means nothing.
    #[cfg(windows)]
    fn shadow_compare_neutral_plan(
        &self,
        sid: &str,
        behavior_mode: nrr_domain::RouteBehaviorMode,
        rule_book: &nrr_domain::canonical::CanonicalRuleBook,
        live: &[nrr_platform_api::types::WfpFilterSpec],
    ) {
        let Some(verdict) = self.neutral_plan_verdict(sid, behavior_mode, rule_book, live) else {
            return;
        };
        if verdict.agrees() {
            tracing::debug!(
                target: "nrr::enforcement-plan",
                sid,
                filters = verdict.live,
                "neutral plan matches the filters actually installed",
            );
            return;
        }
        // A difference is the whole reason this runs on live input. WARN, not
        // debug: it is the one signal that says the neutral path is not ready
        // to take over, and it must not be discoverable only by someone
        // grepping for it.
        tracing::warn!(
            target: "nrr::enforcement-plan",
            sid,
            live = verdict.live,
            neutral = verdict.neutral,
            same_set = verdict.same_set,
            same_order = verdict.same_order,
            only_live = %verdict.only_live,
            only_neutral = %verdict.only_neutral,
            "neutral plan DIFFERS from the filters actually installed — enforcement is unaffected (the live path applied), but the neutral path cannot take over until this is explained",
        );
    }

    /// The comparison itself, separated from the logging so a test can assert
    /// the outcome. A verdict that only ever reaches a log line is a verdict
    /// nothing can hold to account.
    ///
    /// `None` when the SID is not a principal this build can model.
    #[cfg(windows)]
    fn neutral_plan_verdict(
        &self,
        sid: &str,
        behavior_mode: nrr_domain::RouteBehaviorMode,
        rule_book: &nrr_domain::canonical::CanonicalRuleBook,
        live: &[nrr_platform_api::types::WfpFilterSpec],
    ) -> Option<NeutralPlanVerdict> {
        use nrr_platform_api::enforcement::{EnforcementPlan, UserPrincipal};
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let principal = UserPrincipal::from_windows_sid(sid).ok()?;
        let input = crate::enforcement_planner::PlannerInput {
            fqdn_cache: self.fqdn_cache.as_ref(),
            app_resolver: self.app_resolver.as_ref(),
            app_observations: self.app_observations.as_ref(),
            zone_priority_over_ip: false,
        };
        let plan = EnforcementPlan {
            principal,
            flows: crate::enforcement_planner::plan_route_rules(
                rule_book,
                sid,
                behavior_mode,
                &input,
            ),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_route_rules(&plan);

        // `live` is exactly `generate_filters`' output: rule-driven only. The
        // leak-guard and kill-switch classes are appended by the caller further
        // down, after this returns, so no filtering is needed here — and doing
        // any would silently narrow what the comparison covers.
        let difference = nrr_platform_api::wfp_behavioral::behavioral_difference(live, &lowered);
        Some(NeutralPlanVerdict {
            live: live.len(),
            neutral: lowered.len(),
            same_set: behaviorally_equivalent(live, &lowered),
            same_order: arbitration_order_preserved(live, &lowered),
            only_live: render_difference(&difference.only_in_a),
            only_neutral: render_difference(&difference.only_in_b),
        })
    }

    // `compute_filters_for_sid` lives in `per_sid_orchestrator::plan` — same
    // inherent impl, split across files because one method should not be a
    // quarter of the type.
}

/// Choose the behaviour mode the codegen sees for a SID. The per-SID
/// policy's `mode` always wins over the active revision's default —
/// individual users can opt into `StrictSecondaryFailClosed` even on a
/// `PreferPrimary` default profile.
fn behavior_mode_for_codegen(
    policy: &PerSidPolicySnapshot,
    _revision_default: RouteBehaviorMode,
) -> RouteBehaviorMode {
    // The two enums share variant names — keep the mapping by hand
    // so a future divergence (extra variant on one side) becomes a
    // compile error.
    match policy.mode {
        PerSidBehaviorMode::PreferPrimary => RouteBehaviorMode::PreferPrimary,
        PerSidBehaviorMode::PreferSecondaryWhenAvailable => {
            RouteBehaviorMode::PreferSecondaryWhenAvailable
        }
        PerSidBehaviorMode::StrictSecondaryFailClosed => {
            RouteBehaviorMode::StrictSecondaryFailClosed
        }
    }
}

/// Wire `orchestrator` into `registry` so membership changes drive
/// install / remove cycles. The listener is held by an `Arc` inside
/// the registry; `orchestrator` must outlive the registry (production
/// wiring keeps both for the service lifetime).
///
/// Errors are dropped — they cannot propagate through the listener
/// signature. A future version may funnel them into a health-component
/// `Blocking` record (block 16.8.3.4 audit work).
pub fn wire_orchestrator_to_registry(
    orchestrator: Arc<PerSidApplyOrchestrator>,
    registry: &ActiveSidRegistry,
) {
    let orch = Arc::clone(&orchestrator);
    registry.add_listener(Arc::new(move |snapshot: &[String]| {
        // Errors at this layer are logged via tracing — there's no
        // back-channel to the original `on_connect` caller (which is
        // the IPC accept thread). The audit subsystem in 16.8.3.4
        // will surface them through `HealthComponent::Apply`.
        if let Err(e) = orch.reconcile(snapshot) {
            tracing::error!(
                target: "nrr::per_sid_orchestrator",
                "reconcile failed: {e:?}",
            );
        }
    }));
}

/// "who is the routing user with no tray connected?"
/// Production wiring answers with the route coordinator's console-session
/// fallback (`effective_routing_sid(&[])`), so the WFP half and the route half
/// agree on the enforced user even when no tray/GUI process is running.
pub type FallbackRoutingSidFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// + , B2) — production [`RoutePolicyApplyTrigger`].
///
/// Fired by `RoutePolicyUpdateHandler` after a successful per-SID policy
/// write. Recompiles the caller's WFP filters ONLY if the SID is currently
/// routing-active: tray-connected (`ActiveSidRegistry::active_sids`) or —
/// block 16.HW-0716 (P0) — the effective routing user under the configured
/// fallback (console-session user, service-driven scope). Without the
/// fallback, a policy update pushed from a GUI-only connection while the tray
/// subscription was dead was silently skipped (0716 run 2: kill-switch
/// re-enable never recompiled). For any other inactive SID the new policy is
/// picked up when it next becomes routing-active via `reconcile`. Errors are
/// logged, never propagated — the policy is already durably written.
///
/// [`RoutePolicyApplyTrigger`]: crate::ipc_handlers::providers::RoutePolicyApplyTrigger
pub struct OrchestratorRoutePolicyApplyTrigger {
    orchestrator: Arc<PerSidApplyOrchestrator>,
    registry: Arc<ActiveSidRegistry>,
    fallback_routing_sid: Option<FallbackRoutingSidFn>,
    /// "is this SID routing-paused?". A
    /// policy edit (e.g. reset-to-baseline) by a paused user must NOT reinstall
    /// their WFP filters — the other three enforcement paths already subtract
    /// paused SIDs, but this trigger did not, so a paused console user's
    /// fail-closed block could snap back on. Fail-CLOSED to "paused" (skip the
    /// recompile) on a read error, mirroring the reconcile listener.
    paused_check: Option<TriggerPausedCheckFn>,
}

/// predicate: does `sid` have routing paused right now?
pub type TriggerPausedCheckFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

impl OrchestratorRoutePolicyApplyTrigger {
    pub fn new(
        orchestrator: Arc<PerSidApplyOrchestrator>,
        registry: Arc<ActiveSidRegistry>,
    ) -> Self {
        Self {
            orchestrator,
            registry,
            fallback_routing_sid: None,
            paused_check: None,
        }
    }

    /// attach the no-tray routing-user fallback.
    #[must_use]
    pub fn with_fallback_routing_sid(mut self, fallback: FallbackRoutingSidFn) -> Self {
        self.fallback_routing_sid = Some(fallback);
        self
    }

    /// attach the routing-pause predicate so
    /// a policy edit by a paused user does not reinstall their WFP filters.
    #[must_use]
    pub fn with_paused_check(mut self, check: TriggerPausedCheckFn) -> Self {
        self.paused_check = Some(check);
        self
    }
}

impl crate::ipc_handlers::providers::RoutePolicyApplyTrigger
    for OrchestratorRoutePolicyApplyTrigger
{
    fn on_policy_changed(&self, sid: &str) {
        let tray_active = self.registry.active_sids().iter().any(|s| s == sid);
        let console_active = !tray_active
            && self
                .fallback_routing_sid
                .as_ref()
                .and_then(|f| f())
                .as_deref()
                == Some(sid);
        if !tray_active && !console_active {
            // Not routing-active — the new policy applies when the SID next
            // becomes routing-active via the reconcile listener. Installing now
            // would create filters for a user nothing is enforcing for.
            return;
        }
        // a routing-PAUSED SID must not have
        // its filters reinstalled by a policy edit (reset-to-baseline, a rule
        // change). Pause means "no enforcement" — the same invariant the
        // reconcile listener and the recompute hook already honour. Fail-CLOSED
        // to paused on a read error (the predicate wraps that), so a transient
        // DB error can never re-arm a paused user's block-all.
        if self.paused_check.as_ref().is_some_and(|check| check(sid)) {
            tracing::info!(
                target: "nrr::per_sid_orchestrator",
                sid,
                "policy changed for a routing-paused SID — not recompiling filters (pause = no enforcement)",
            );
            return;
        }
        match self.orchestrator.recompile_for_sid(sid) {
            Ok(count) => tracing::info!(
                target: "nrr::per_sid_orchestrator",
                filter_count = count,
                "route policy changed: recompiled WFP filters for active SID",
            ),
            Err(e) => tracing::error!(
                target: "nrr::per_sid_orchestrator",
                "route policy recompile failed: {e:?}",
            ),
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

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

// ── Tests ────────────────────────────────────────────────────────────────────

mod apply;
mod builder;
mod plan;
#[cfg(test)]
mod tests;

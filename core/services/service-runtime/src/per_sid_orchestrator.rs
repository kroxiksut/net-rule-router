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
//! Real rule-engine integration (`decide_route` from `nrr-domain`)
//! lives behind the `nrr-domain::decision_engine` API and depends on
//! the rules-table schema that block 16.10 introduces. Until then the
//! orchestrator runs end-to-end with a placeholder filter set, which
//! is enough to prove:
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
use nrr_platform_api::types::{WfpAction, WfpFilterAction, WfpFilterId, WfpFilterSpec};
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

/// Filters the orchestrator currently has installed for one SID.
#[derive(Clone, Debug, Default)]
pub struct PerSidFilterSet {
    pub sid: String,
    pub installed: Vec<WfpFilterId>,
}

/// Result of deriving a SID's WFP filter set from its current policy, rules,
/// and FQDN cache (see [`PerSidApplyOrchestrator::compute_filters_for_sid`]).
/// Split out so the initial [`PerSidApplyOrchestrator::install_for_sid`] and
/// the incremental [`PerSidApplyOrchestrator::reconcile_secondary_coverage`]
/// share exactly one filter-derivation path.
enum ComputedFilterSet {
    /// The SID installs `filters` (rule-driven Permit/Block + leak-guard).
    Install(Vec<WfpFilterSpec>),
    /// The SID has no per-SID policy row → installs nothing.
    NoPolicy,
    /// The SID has a policy but no active rule revision → installs nothing.
    NoActiveRules,
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

pub struct PerSidApplyOrchestrator {
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

/// One compute's kill-switch/fail-closed BLOCK ids, split by blocking scope.
/// `app_scoped` is the subset of `all` whose blocks carry only an app-id
/// condition — see [`crate::killswitch_drop_registry`] for why the drop
/// detector must keep the two apart.
#[derive(Debug, Default, Clone)]
struct KillswitchBlockIds {
    all: HashSet<u64>,
    app_scoped: HashSet<u64>,
}

impl KillswitchBlockIds {
    fn is_empty(&self) -> bool {
        self.all.is_empty()
    }
}

/// Fold every BLOCK-action spec's id into `into` — the accumulator behind the
/// reactive VPN-endpoint learner's role-verification registry (see
/// [`PerSidApplyOrchestrator::update_killswitch_registry`]). Permit filters in
/// the same batch (e.g. the kill-switch's own egress-conditional permit half)
/// never qualify — only a BLOCK can be the filter that produced a drop.
/// App-only blocks are additionally recorded as app-scoped.
fn collect_block_ids(specs: &[WfpFilterSpec], into: &mut KillswitchBlockIds) {
    for spec in specs.iter().filter(|s| s.action == WfpAction::Block) {
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
        && spec.remote_subnet.is_none()
        && spec.remote_subnet_v6.is_none()
}

impl PerSidApplyOrchestrator {
    pub fn new(
        session: Arc<WfpSession>,
        policy_source: Arc<dyn RoutePolicySource>,
        rules_provider: Arc<dyn RulesProvider>,
        fqdn_cache: Arc<dyn FqdnCacheLookup>,
        audit: Arc<dyn PerSidApplyAudit>,
    ) -> Self {
        Self {
            session,
            policy_source,
            rules_provider,
            fqdn_cache,
            audit,
            // Default to the product default (best-effort). Production
            // overrides via `with_failure_mode_source` to track the
            // admin's persisted `ApplyFailurePolicy`.
            failure_mode: Arc::new(|| FilterFailureMode::BestEffort),
            // Default: kill-switch off (unresolved). Production overrides
            // via `with_kill_switch_resolver`.
            kill_switch_resolver: Arc::new(|_| None),
            // Default: no extra exemptions. Production overrides via
            // `with_fail_closed_exemptions_resolver`.
            fail_closed_exemptions_resolver: Arc::new(|_| FailClosedExemptions::default()),
            // Default: no verified VPN clients. Production wires the learned
            // registry via `with_vpn_client_apps_provider`.
            vpn_client_apps_provider: None,
            // Default: empty observation store → app rules route nothing.
            // Production overrides via `with_app_observations`.
            app_observations: Arc::new(AppObservationStore::new()),
            // Default: no app-path resolver → app rules resolve nothing (unwired
            // = today's no-app-id behaviour, now surfaced as an `AppUnresolved`
            // diagnostic instead of a silent apply-skip). Production overrides
            // via `with_app_resolver`.
            app_resolver: Arc::new(nrr_platform_api::NoopAppPathResolver),
            state: Mutex::new(HashMap::new()),
            // Default: no on-disk ledger. Production wires one via
            // `with_filter_ledger` so hard-kill orphans self-heal.
            ledger: None,
            // Default: no shared status → `AppUnresolved` diagnostics are
            // INFO-logged only. Production wires one via
            // `with_app_enforcement_status` so the GUI banner can list them.
            app_enforcement_status: None,
            // Default: no shared status → smart-kill-switch exclusions are
            // logged only. Production wires one via
            // `with_shared_ip_exemption_status` for the GUI warning.
            shared_ip_exemption_status: None,
            // Default: no-op flush. Production wires the per-OS mechanism
            // via `with_dns_cache_control`.
            dns_cache_control: Arc::new(nrr_platform_api::NoopDnsCacheControl),
            block_all_flush_state: Mutex::new(HashMap::new()),
            posture_log_state: Mutex::new(HashMap::new()),
            // Default: fake-IP out of the plan. Production wires a live
            // provider via `with_fake_ip_context_provider`.
            fake_ip_context: Arc::new(|| None),
            // Default: no known-direct exemptions (strict block-all).
            // Production wires the session registry via
            // `with_known_direct_registry`.
            known_direct: None,
            // Default: no shared posture status → block-all state is log-only.
            // Production wires one via `with_block_all_posture_status`.
            block_all_posture_status: None,
            // Default: no registry → the reactive VPN-endpoint learner's
            // role-verification gate stays permanently closed. Production
            // wires one via `with_killswitch_drop_registry`.
            killswitch_drop_registry: None,
            killswitch_block_ids_by_sid: Mutex::new(HashMap::new()),
            // Default: historical ordering (blocks install without first
            // driving the route pass). Production wires the route coordinator
            // via `with_route_sync`.
            route_sync: None,
            // Default: nobody listens, so a persisting fail-closed posture only
            // announces itself. Production wires the watchdog's queue via
            // `with_rebind_requests`.
            rebind_requests: None,
        }
    }

    /// Wire the queue the resume watchdog drains. A fail-closed posture that
    /// keeps blocking is asked to re-resolve its binding on every heartbeat —
    /// the request is a flag, so the recompute runs on the watchdog's thread,
    /// never re-entering the apply path from inside a compute.
    #[must_use]
    pub fn with_rebind_requests(
        mut self,
        requests: Arc<crate::power_resume::RebindRequests>,
    ) -> Self {
        self.rebind_requests = Some(requests);
        self
    }

    /// Wire the "route before block" ordering hook: the reconcile calls it
    /// immediately before installing a destination-scoped BLOCK it was not
    /// already tracking, so the destination's secondary `/32` is in place
    /// before the block that only tolerates secondary egress. Skipped
    /// entirely when a reconcile adds no new destination block, so the steady
    /// state costs nothing.
    #[must_use]
    pub fn with_route_sync(mut self, hook: RouteSyncHook) -> Self {
        self.route_sync = Some(hook);
        self
    }

    /// wire the shared "block-all armed" posture the GUI
    /// banner reads via `SnapshotInitial`.
    #[must_use]
    pub fn with_block_all_posture_status(
        mut self,
        status: crate::app_enforcement_status::BlockAllPostureStatus,
    ) -> Self {
        self.block_all_posture_status = Some(status);
        self
    }

    /// Wire the kill-switch/fail-closed Block-id registry so the reactive
    /// VPN-endpoint learner can role-verify a drop. Every filter compute
    /// republishes this SID's current kill-switch/fail-closed BLOCK id set
    /// (see [`Self::killswitch_block_ids_by_sid`]). Without it the registry
    /// stays empty and the learner's gate never opens.
    #[must_use]
    pub fn with_killswitch_drop_registry(
        mut self,
        registry: Arc<crate::killswitch_drop_registry::KillswitchBlockFilterRegistry>,
    ) -> Self {
        self.killswitch_drop_registry = Some(registry);
        self
    }

    /// Record `sid`'s current kill-switch/fail-closed BLOCK id set and
    /// republish the union across every SID this orchestrator has computed
    /// for, to the shared registry. An empty `ids` removes `sid`'s entry
    /// (its leak-guard disarmed or its policy is gone) rather than leaving a
    /// stale set that could role-verify a drop that no longer applies. No-op
    /// when no registry is wired.
    fn update_killswitch_registry(&self, sid: &str, ids: KillswitchBlockIds) {
        let Some(registry) = self.killswitch_drop_registry.as_ref() else {
            return;
        };
        let mut by_sid = self
            .killswitch_block_ids_by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if ids.is_empty() {
            by_sid.remove(sid);
        } else {
            by_sid.insert(sid.to_string(), ids);
        }
        let all: HashSet<u64> = by_sid
            .values()
            .flat_map(|v| v.all.iter())
            .copied()
            .collect();
        let app_scoped: HashSet<u64> = by_sid
            .values()
            .flat_map(|v| v.app_scoped.iter())
            .copied()
            .collect();
        registry.publish_scoped(all, app_scoped);
    }

    /// Proactive VPN-client exemption — wire the verified
    /// VPN-client path provider so a known client is permitted through a
    /// block-all posture at ARMING time, before its first drop of the session.
    #[must_use]
    pub fn with_vpn_client_apps_provider(mut self, provider: VpnClientAppsProvider) -> Self {
        self.vpn_client_apps_provider = Some(provider);
        self
    }

    /// wire the known-direct registry so the block-all
    /// exempts destinations positively established as direct (non-rule) hosts.
    #[must_use]
    pub fn with_known_direct_registry(
        mut self,
        registry: Arc<crate::known_direct::KnownDirectRegistry>,
    ) -> Self {
        self.known_direct = Some(registry);
        self
    }

    /// whether ANY tracked SID currently has the fail-closed
    /// catch-all block-all armed. The Mode-B direct-answer gate keys on this: a
    /// direct host needs its exemption installed BEFORE the answer only while
    /// the catch-all is armed.
    pub fn any_block_all_armed(&self) -> bool {
        self.block_all_flush_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .any(|armed| *armed)
    }

    /// Block D (fake-IP, slice 5) — wire the LIVE fake-IP context provider,
    /// consulted on every compute, so the per-SID codegen suppresses
    /// fake-routed hosts' real `/32` permits, permits the fake pool, and
    /// hard-blocks their non-shared real IPs exactly while the feature is
    /// actually on. See [`FakeIpContextProvider`] for why the read must be
    /// live. A `None` (or disabled-scope) yield is a no-op.
    #[must_use]
    pub fn with_fake_ip_context_provider(mut self, provider: FakeIpContextProvider) -> Self {
        self.fake_ip_context = provider;
        self
    }

    /// Record the kill-switch posture derived by THIS compute and report
    /// whether it differs from the last one logged for the SID. Callers log
    /// at full level on `true` (a real posture change) and at `debug` on
    /// `false` (the ~5 s reconcile re-deriving the same state). A
    /// transition-only view over [`Self::posture_log_event`] for callers
    /// that don't want a periodic heartbeat while the posture persists.
    fn posture_changed(&self, sid: &str, posture: &'static str) -> bool {
        !matches!(
            self.posture_log_event_with_interval(sid, posture, Duration::MAX),
            PostureLogEvent::Steady
        )
    }

    /// Same latch as [`Self::posture_changed`], but also re-announces at
    /// full level every [`POSTURE_HEARTBEAT_INTERVAL`] while the posture
    /// persists unchanged, so a long-lived state (e.g. the kill-switch
    /// fail-closed block-all) still leaves a periodic trail instead of
    /// going silent for the whole session after its first line.
    fn posture_log_event(&self, sid: &str, posture: &'static str) -> PostureLogEvent {
        self.posture_log_event_with_interval(sid, posture, POSTURE_HEARTBEAT_INTERVAL)
    }

    fn posture_log_event_with_interval(
        &self,
        sid: &str,
        posture: &'static str,
        heartbeat_interval: Duration,
    ) -> PostureLogEvent {
        let mut g = self
            .posture_log_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let prior = g.get(sid).copied();
        let (event, latch) =
            evaluate_posture_log(prior, posture, Instant::now(), heartbeat_interval);
        g.insert(sid.to_string(), latch);
        event
    }

    /// wire the on-disk filter-id ledger so
    /// installed ids are persisted and a hard-killed prior instance's orphans
    /// can be reaped by id at the next start (see [`Self::cleanup_persisted_orphans`]).
    pub fn with_filter_ledger(
        mut self,
        ledger: Arc<crate::wfp_filter_ledger::WfpFilterLedger>,
    ) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Override the per-filter apply-failure mode source. Production
    /// wires this to the live `ApplyFailurePolicy` so the
    /// strict / best-effort choice in Settings governs whether one
    /// un-materializable rule rolls back the whole revision.
    pub fn with_failure_mode_source(mut self, source: FilterFailureModeSource) -> Self {
        self.failure_mode = source;
        self
    }

    /// wire the kill-switch resolver.
    /// Without this the kill-switch is inert (the default resolver always
    /// returns `None`). Production passes a closure that resolves the
    /// active user's secondary binding + exemptions through the route
    /// coordinator; the kill-switch then activates only when the user has
    /// also turned on `block_secondary_when_unavailable`.
    pub fn with_kill_switch_resolver(mut self, resolver: KillSwitchResolver) -> Self {
        self.kill_switch_resolver = resolver;
        self
    }

    /// wire the fail-closed exemptions resolver. Only
    /// consulted on the fail-closed path when the secondary is unresolvable
    /// (mode B block-all). Without it, block-all still exempts loopback /
    /// link-local / broadcast but not LAN — production should wire this so a
    /// fail-closed user keeps local manageability and tunnel reconnection.
    pub fn with_fail_closed_exemptions_resolver(
        mut self,
        resolver: FailClosedExemptionsResolver,
    ) -> Self {
        self.fail_closed_exemptions_resolver = resolver;
        self
    }

    /// App-routing via observation — wire the observed app→IP
    /// store the codegen reads for `Application` rules. Without it the default
    /// empty store is used and app rules route nothing. Production passes the
    /// same store the connection-observation consumer writes into.
    pub fn with_app_observations(mut self, store: Arc<dyn AppObservationLookup>) -> Self {
        self.app_observations = store;
        self
    }

    /// wire the app-path resolver the codegen uses to turn an
    /// `Application` rule's exe name/glob into concrete on-disk exe paths (so it
    /// can emit real per-app `ALE_APP_ID` filters). Without it the default
    /// [`nrr_platform_api::NoopAppPathResolver`] resolves nothing and app
    /// rules install no per-process enforcement (surfaced as
    /// [`crate::wfp_codegen::CodegenDiagnostic::AppUnresolved`]). Production
    /// passes a [`nrr_platform_api::WindowsAppPathResolver`].
    pub fn with_app_resolver(
        mut self,
        resolver: Arc<dyn nrr_platform_api::AppPathResolver>,
    ) -> Self {
        self.app_resolver = resolver;
        self
    }

    /// wire the shared status the codegen's `AppUnresolved`
    /// diagnostics publish into on every filter compute, so the
    /// `SnapshotInitial` handler can surface a GUI banner listing app rules
    /// that resolved to no exe path (and are therefore unenforced). Without
    /// it the diagnostics are INFO-logged only.
    pub fn with_app_enforcement_status(
        mut self,
        status: crate::app_enforcement_status::AppEnforcementStatus,
    ) -> Self {
        self.app_enforcement_status = Some(status);
        self
    }

    /// wire the shared count of secondary IPs the
    /// "smart" kill-switch excluded from its pin/block set because the
    /// shared-IP census saw them on direct (non-rule) hosts too. The
    /// `SnapshotInitial` handler reads it for the GUI's "strictness reduced
    /// for N shared IPs" warning. Without it the exclusions are logged only.
    pub fn with_shared_ip_exemption_status(
        mut self,
        status: crate::app_enforcement_status::SharedIpExemptionStatus,
    ) -> Self {
        self.shared_ip_exemption_status = Some(status);
        self
    }

    /// wire the OS resolver-cache flush mechanism.
    /// Fired only on the fail-closed block-all arming/disarming edge so names
    /// cached by the OS resolver before the block armed are re-queried on the
    /// wire, become observable, and earn their suffix/zone permits. Without it
    /// the default no-op leaves the pre-block OS cache in place (tests /
    /// degraded boot / platforms without a flushable cache).
    pub fn with_dns_cache_control(
        mut self,
        control: Arc<dyn nrr_platform_api::DnsCacheControlPort>,
    ) -> Self {
        self.dns_cache_control = control;
        self
    }

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
        block_all: bool,
    ) -> Vec<WfpFilterSpec> {
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
                    crate::killswitch_codegen::fail_closed_block_destinations(
                        sid, &protected, protocols,
                    )
                }
            }
            RouteBehaviorMode::PreferSecondaryWhenAvailable
            | RouteBehaviorMode::StrictSecondaryFailClosed => {
                crate::killswitch_codegen::fail_closed_block_all_filters(sid, exemptions, protocols)
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

    fn compute_filters_for_sid(
        &self,
        sid: &str,
        log_unresolved: bool,
        rules_override: Option<&ActiveRulesSnapshot>,
    ) -> Result<ComputedFilterSet, OrchestratorError> {
        if sid.is_empty() {
            return Err(OrchestratorError::EmptySid);
        }
        // the admin baseline is never enforced as its own
        // machine-wide filter set (see `install_for_sid`).
        if sid == nrr_domain::user_principal::BASELINE_PRINCIPAL {
            return Err(OrchestratorError::BaselineNotRoutable);
        }
        let policy = match self.policy_source.load_for_sid(sid) {
            Some(s) => s,
            None => {
                // no enforceable policy → no
                // app rules are unenforced; clear any stale unresolved-app set so
                // the GUI banner does not keep listing a now-phantom app.
                self.clear_app_enforcement_status();
                // policy gone ⇒ any block-all is disarming.
                self.note_block_all_state(sid, false);
                // No policy ⇒ no kill-switch filters either; drop any stale
                // entry so the registry never role-verifies a drop for a SID
                // whose leak-guard is no longer armed.
                self.update_killswitch_registry(sid, KillswitchBlockIds::default());
                return Ok(ComputedFilterSet::NoPolicy);
            }
        };
        // an activation dispatch runs BEFORE the
        // active-revision pointer commits (all-or-nothing: revert must stay
        // possible), so a storage read here would still see the PREVIOUS
        // revision. The dispatcher passes the revision content it is applying;
        // every other caller reads the active pointer as before.
        let rules = match rules_override
            .cloned()
            .or_else(|| self.rules_provider.active_rules_for(sid))
        {
            Some(r) => r,
            None => {
                self.clear_app_enforcement_status();
                // rules gone ⇒ any block-all is disarming.
                self.note_block_all_state(sid, false);
                self.update_killswitch_registry(sid, KillswitchBlockIds::default());
                return Ok(ComputedFilterSet::NoActiveRules);
            }
        };
        // surface the DELIVERED app-match patterns (exactly what
        // reached this SID's ACTIVE rule set). A "no exe matched" report can then
        // be triaged: pattern ABSENT here ⇒ the GUI edit never reached the service
        // (a delivery/persist problem, C1 family); pattern PRESENT but later logged
        // as unresolved ⇒ a resolver/enumeration problem. Logged once per apply
        // (`log_unresolved`), never on a reconcile tick.
        if log_unresolved {
            let app_pattern = |r: &nrr_domain::canonical::CanonicalRule| -> Option<String> {
                r.app_match.as_ref().map(|a| match &a.pattern {
                    nrr_domain::canonical::CanonicalAppPattern::Exact(s)
                    | nrr_domain::canonical::CanonicalAppPattern::Glob(s) => s.clone(),
                })
            };
            let primary_apps: Vec<String> = rules
                .rule_book
                .primary
                .rules()
                .iter()
                .filter_map(app_pattern)
                .collect();
            let secondary_apps: Vec<String> = rules
                .rule_book
                .secondary
                .rules()
                .iter()
                .filter_map(app_pattern)
                .collect();
            if !primary_apps.is_empty() || !secondary_apps.is_empty() {
                tracing::info!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    primary_app_rules = primary_apps.join(", "),
                    secondary_app_rules = secondary_apps.join(", "),
                    "delivered app-match rules for this SID (apply)",
                );
            }
        }

        // swap: route the policy's behaviour-mode through the codegen.
        let behavior_mode = behavior_mode_for_codegen(&policy, rules.behavior_mode);
        // shared-IP denylist from the SAME enforcement rule
        // book + live cache the codegen reads, so the WFP set and the route
        // table decline the same shared IPs coherently.
        let mut secondary_ip_denylist = crate::secondary_ip_policy::secondary_ip_denylist(
            &rules.rule_book.secondary,
            self.fqdn_cache.as_ref(),
            policy.shared_ip_policy,
        );
        // Block D (fake-IP, slice 5) — fold fake-IP into the plan. Computed
        // against the ORIGINAL denylist (which doubles as the shared-IP census),
        // BEFORE its suppress-set is merged in: the /32 permits of shared real
        // addresses are suppressed via the denylist, and the pool permit is
        // appended after codegen. The context is resolved
        // LIVE for this compute; a `None` / disabled context is a no-op, so the
        // non-fake-IP path is byte-for-byte unchanged.
        let fake_ip_context = (self.fake_ip_context)();
        // Fake-IP UDP relay — process-wide live flag, read fresh on
        // every compute (mirrors how the fake-IP context itself is resolved
        // live above) so a toggle takes effect on the very next replan.
        let udp_relay_enabled =
            crate::fake_ip::global_udp_relay_enabled().load(std::sync::atomic::Ordering::Relaxed);
        let fake_ip_augmentation = fake_ip_context.as_ref().map(|ctx| {
            crate::fake_ip::augment_codegen_for_fake_ip(
                sid,
                ctx,
                &rules.rule_book.secondary,
                self.fqdn_cache.as_ref(),
                &secondary_ip_denylist,
                udp_relay_enabled,
            )
        });
        if let Some(aug) = &fake_ip_augmentation {
            secondary_ip_denylist.extend(aug.denylist_additions.iter().copied());
        }
        //  — republish this SID's user-confirmed link-provider
        // executables before anything resolves an app pattern. Two consumers
        // read the registry: the app-path resolver, which materializes a
        // confirmed client's `ALE_APP_ID` permit even though the process has
        // never run (breaking the "permit only exists once the client is up"
        // chicken-and-egg), and the fake-IP relay, which keeps that client's own
        // flows off the link it is establishing. Publishing here — inside the
        // compute, ahead of `generate_filters` — is what makes the resolver see
        // the current pick with no extra wiring, and clearing it (the user
        // un-confirms) revokes both on the very next compute.
        crate::vpn_client_registry::global_confirmed_vpn_clients()
            .publish(sid, &policy.link_provider_exe_paths);
        let mut codegen_out = generate_filters(CodegenInput {
            sid,
            rule_book: &rules.rule_book,
            behavior_mode,
            fqdn_cache: self.fqdn_cache.as_ref(),
            app_observations: self.app_observations.as_ref(),
            app_resolver: self.app_resolver.as_ref(),
            secondary_ip_denylist: &secondary_ip_denylist,
        });
        if let Some(aug) = fake_ip_augmentation {
            codegen_out.filters.extend(aug.extra_filters);
        }
        // surface app rules whose exe could not be resolved to
        // a path (app not installed / not running / not in App Paths) so they are
        // not silently unenforced. The rule's observation /32 mirrors (if any)
        // still apply; only the direct per-process ALE_APP_ID filter is absent.
        // Besides the WARN log we publish the set into the shared
        // `AppEnforcementStatus` (when wired) so the SnapshotInitial handler
        // can drive a GUI banner. WARN (not INFO): a rule that silently
        // enforces nothing is worth a look, not just a diagnostic trail.
        let mut unresolved_apps: Vec<String> = Vec::new();
        let mut over_capped: Vec<String> = Vec::new();
        // suffix/zone rules whose cached-hostname fan-out
        // hit `SUFFIX_FANOUT_BACKSTOP`, meaning the cache holds at least as many
        // subdomains as the cap and some were silently dropped from enforcement.
        let mut truncated_suffixes: Vec<(String, String, usize)> = Vec::new();
        for diag in &codegen_out.diagnostics {
            match diag {
                crate::wfp_codegen::CodegenDiagnostic::AppUnresolved { app, .. } => {
                    unresolved_apps.push(app.clone());
                }
                crate::wfp_codegen::CodegenDiagnostic::AppOverCapped {
                    app, resolved, cap, ..
                } => {
                    over_capped.push(format!("{app} ({cap}/{resolved})"));
                }
                crate::wfp_codegen::CodegenDiagnostic::SuffixTruncated {
                    rule_id,
                    suffix,
                    cap,
                } => {
                    truncated_suffixes.push((rule_id.clone(), suffix.clone(), *cap));
                }
                _ => {}
            }
        }
        // log app-enforcement diagnostics ONLY on a real
        // (re)apply (`install_for_sid`, `log_unresolved = true`), NEVER on the
        // background reconcile / leak-guard tick (`reconcile_secondary_coverage`),
        // which fires every few seconds and re-derived the SAME set 658× last
        // session → 35,532 identical lines (95% of the whole operational log). One
        // aggregated line per apply instead of one-per-rule. The
        // `AppEnforcementStatus` set (the GUI banner source) is refreshed every
        // tick below regardless, so the user-facing signal never goes stale — this
        // trims log volume only, not enforcement or the GUI notice.
        if log_unresolved {
            if !unresolved_apps.is_empty() {
                tracing::warn!(
                    target: "nrr::app-resolver",
                    sid = %sid,
                    count = unresolved_apps.len(),
                    apps = %unresolved_apps.join(", "),
                    "application rules not enforced: no installed/running exe matched (checked App Paths, running processes, Program Files) — the per-app filters were not built",
                );
            }
            if !over_capped.is_empty() {
                tracing::warn!(
                    target: "nrr::app-resolver",
                    sid = %sid,
                    count = over_capped.len(),
                    apps = %over_capped.join(", "),
                    "application rules PARTIALLY enforced: exe name/glob resolved to more paths than the per-app filter cap (app: cap/resolved)",
                );
            }
            for (rule_id, suffix, cap) in &truncated_suffixes {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    sid = %sid,
                    rule_id = %rule_id,
                    suffix = %suffix,
                    cap = *cap,
                    "suffix/zone rule matched more than cap cached hosts; only the cap most-recently-seen were given permits — narrow the rule or upgrade for uncapped zones",
                );
            }
        }
        if let Some(status) = self.app_enforcement_status.as_ref() {
            status.set_unresolved(unresolved_apps);
        }
        let mut filters = codegen_out.filters;
        // Reactive VPN-endpoint learning — every kill-switch/fail-closed BLOCK
        // filter spec id emitted for THIS sid below is collected here (rule
        // filters above are never included), then published to the shared
        // registry at the end of this compute (see `update_killswitch_registry`).
        let mut killswitch_block_ids = KillswitchBlockIds::default();
        // arm the leak-guard ("Защита от утечки")
        // WHENEVER a secondary (additional) adapter is CONFIGURED for this SID.
        // Binding a secondary is itself the request to route that traffic
        // through it; the instant the adapter becomes unresolvable (secondary adapter down /
        // not started / stale GUID) `resolve()` returns `None` and the
        // fail-closed branch below blocks rather than leaking to the primary —
        // and stays armed until the binding resolves again (auto-heal) or the
        // user clears/reassigns the secondary. The explicit
        // `block_secondary_when_unavailable` toggle and the strict fail-closed
        // mode still force-arm even with no secondary bound. The user's
        // fail-OPEN escape hatch is the posture flag `kill_switch_fail_closed =
        // false` (handled in both branches below), NOT disarming the guard.
        //
        // Before 0706 this gated ONLY on the opt-in toggle, which the GUI write
        // path defaulted to `false` (RoutingSettings opt-in + serde default) —
        // so a user who bound a secondary adapter but never found+ticked the toggle had leak
        // protection silently OFF and leaked to the primary the moment the secondary adapter
        // dropped  HW test symptoms #2/#8: zero kill-switch codegen
        // log lines for the whole run).
        // the MASTER kill-switch toggle gates the ENTIRE
        // leak-guard: if the user has not explicitly enabled the kill-switch, NO
        // fail-closed blocking arms at all (full opt-in — any leak while the
        // secondary is down is then the user's deliberate choice). This
        // intentionally supersedes the  auto-arm-on-secondary-bound
        // default: enforcement is now opt-in, per the  UX decision.
        let leak_guard_armed = policy.kill_switch_enabled
            && (policy.secondary.is_some()
                || policy.block_secondary_when_unavailable
                || behavior_mode == RouteBehaviorMode::StrictSecondaryFailClosed);
        // whether THIS compute produced a fail-closed
        // block-all set (feeds the arming-edge OS resolver-cache flush at the
        // end of the function; per-IP pinning and fail-open never flush).
        let mut block_all_armed = false;
        if leak_guard_armed {
            // `fail_closed` (default) → block rather than leak when the leak-proof
            // kill-switch cannot arm because the secondary is unresolvable.
            let fail_closed = policy.kill_switch_fail_closed;
            let protocols = crate::killswitch_codegen::KillSwitchProtocols::from_bits(
                policy.kill_switch_protocols,
            );
            // the Mode-A coverage strategy decides how a
            // routed domain's UN-SEEDED edge IP is handled when the secondary is
            // unresolved (VPN down). `FailClosedUnknown` escalates the fail-closed
            // block to the catch-all so that un-seeded IP is BLOCKED rather than
            // leaked to the primary (the  chatgpt-over-primary leak while
            // the VPN was closed). This only escalates in PreferPrimary (Mode A) —
            // the other modes already catch-all — and only in the `None`
            // (secondary-unresolved) branch below; while the secondary is UP the
            // per-IP pin is correct and a catch-all would wrongly cut the primary.
            // `ZoneWidening` is not yet implemented (needs suffix/zone routing) and
            // falls back to per-IP with a one-line notice; `FailClosedUnknown` is
            // the default since HW-0714.
            use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
            let mode_a_fail_closed_unknown = behavior_mode == RouteBehaviorMode::PreferPrimary
                && policy.mode_a_coverage_strategy == ModeACoverageStrategy::FailClosedUnknown;
            if policy.mode_a_coverage_strategy == ModeACoverageStrategy::ZoneWidening {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    "mode-A coverage strategy 'zone-widening' selected but not yet enforced — falling back to per-IP pinning",
                );
            }
            // apps the user explicitly routed to the PRIMARY adapter
            // are EXEMPT from the kill-switch: an always-permit by app-id so a VPN
            // client placed on primary can always reach its server and the tunnel
            // comes up instead of being blocked (the bootstrap deadlock fix). The
            // built-in common-VPN-client exemptions are merged in so this works out
            // of the box; the user's own primary-app rules augment the set. Deduped
            // so a path named by both sources emits a single filter (ids are
            // path-derived).
            //
            // the built-in exemptions are the RESOLVED
            // on-disk exe paths (`codegen_out.vpn_default_exempt_paths`), NOT the
            // raw `DEFAULT_VPN_EXEMPT_PATTERNS` globs. The WFP `ALE_APP_ID` condition
            // keys on a real file path, so a glob stamped verbatim into `app_pattern`
            // never installed a permit (the apply layer silently skipped it) — the
            // chicken-and-egg that trapped the VPN under the kill-switch. Both
            // sources here are now concrete paths, so no `app_pattern` carrying a
            // glob (`*`) can ever leave the fail-closed set.
            //
            // fix — these permits are emitted ONLY inside the BLOCKING
            // branches below (`None` = secondary unresolved, the empty Some
            // path, and — since  — the armed mode-B catch-all), NOT
            // unconditionally. A permit-only exemption is pointless where
            // nothing is blocked (fail-open, or mode A with the secondary UP
            // and routing normally). Computed once here; each blocking branch
            // below folds them in with
            // `primary_app_exempt_filters(sid, &exempt_patterns)`.
            // the user-confirmed link-provider apps join the
            // exemption set: concrete paths from `route_link_provider_apps`,
            // strictly more precise than the built-in glob resolutions.
            //  — VERIFIED VPN clients join too: exe paths learned
            // from role-verified kill-switch drops (see
            // `crate::vpn_client_registry`), covering clients the glob
            // resolver never finds on disk. Deduped case-insensitively —
            // Windows paths; filter ids are path-derived, so two casings of
            // one path would otherwise emit two filters.
            let learned_vpn_client_paths: Vec<String> = self
                .vpn_client_apps_provider
                .as_ref()
                .map(|provider| provider())
                .unwrap_or_default();
            let exempt_patterns: Vec<String> = {
                let mut seen = std::collections::HashSet::new();
                codegen_out
                    .vpn_default_exempt_paths
                    .iter()
                    .cloned()
                    .chain(codegen_out.primary_app_patterns.iter().cloned())
                    .chain(policy.link_provider_exe_paths.iter().cloned())
                    .chain(learned_vpn_client_paths)
                    .filter(|p| seen.insert(p.to_ascii_lowercase()))
                    .collect()
            };
            // "smart" kill-switch shared-IP
            // handling (the default). An IP the shared-IP census has ALSO seen
            // on a direct (non-rule) hostname is removed from the kill-switch
            // pin/block set: IP-level blocking cannot separate co-tenants, and
            // the 0719 HW run showed strict pinning of Google front-end IPs
            // (shared by gemini/youtube secondary rules and www.google.com)
            // killing google.com in every browser — plus the VPN client's own
            // bootstrap. The trade-off is explicit: while excluded, those IPs
            // are not leak-protected (secondary-rule traffic to them can egress
            // the primary when the secondary is down). `strict` restores the
            // historic pin-everything posture. ROUTING (`/32` via the secondary
            // while it is up) is untouched — this governs only the kill-switch
            // and fail-closed block sets. Whether an UNPINNED shared IP may
            // also be RESCUED by a block-all exemption is a separate, fake-IP-
            // gated decision — see `never_exempt_secondary_ips` below.
            let (ks_dest_ips, ks_shared_excluded_ips): (
                Vec<std::net::Ipv4Addr>,
                Vec<std::net::Ipv4Addr>,
            ) = if policy.kill_switch_strict_shared_ips {
                (codegen_out.secondary_dest_ips.clone(), Vec::new())
            } else {
                let shared = self.fqdn_cache.shared_direct_ips();
                if shared.is_empty() {
                    (codegen_out.secondary_dest_ips.clone(), Vec::new())
                } else {
                    let (kept, excluded): (Vec<_>, Vec<_>) = codegen_out
                        .secondary_dest_ips
                        .iter()
                        .copied()
                        .partition(|ip| !shared.contains(ip));
                    (kept, excluded)
                }
            };
            if let Some(status) = self.shared_ip_exemption_status.as_ref() {
                let prev = status.count();
                status.set(&ks_shared_excluded_ips);
                if prev != ks_shared_excluded_ips.len() as u32 && !ks_shared_excluded_ips.is_empty()
                {
                    tracing::info!(
                        target: "nrr::per_sid_orchestrator",
                        sid,
                        excluded = ks_shared_excluded_ips.len(),
                        pinned = ks_dest_ips.len(),
                        "smart kill-switch: shared IPs excluded from the pin/block set (each is also used by a direct host; strict mode pins them regardless)",
                    );
                }
            }
            //  — is hostname-level (fake-IP) enforcement actually
            // covering rule hosts THIS compute? `fake_ip_context` is resolved
            // live above and, in production, is `Some` (with an enabled scope)
            // only when the toggle is on, the enforcement mode is Resolver,
            // AND the TUN relay stack is running — the desired-AND-running
            // signal, not merely the persisted toggle.
            let fake_ip_name_enforcement_active = fake_ip_context
                .as_ref()
                .is_some_and(|ctx| ctx.scope.is_enabled());
            // The subtraction base for every exemption set below (known-primary
            // transport permits, known-direct rescues): an IP in this set must
            // NEVER be rescued by an exemption while the secondary is down.
            // Two modes:
            //
            // - Fake-IP EFFECTIVE → subtract only the IPs actually PINNED this
            //   compute (`ks_dest_ips`, the  relaxation). A
            //   census-shared IP the smart kill-switch declined to pin stays
            //   exemptible, so its direct co-tenant (workspace.google.com
            //   sharing a front-end IP with a secondary rule host) is not
            //   blocked to death on a link that carries nothing. Safe ONLY
            //   because the rule host itself is still enforced BY NAME: the
            //   fake-IP answerer hands it a virtual address and the relay owns
            //   the flow, so the shared real IP is a side channel the rule
            //   host does not use.
            // - Fake-IP NOT effective (toggle off, non-Resolver mode, or the
            //   datapath is down) → strict subtraction of ALL secondary
            //   destination IPs, census-shared included. The IP pin/block set is
            //   then the ONLY enforcement, and an exempted shared IP is a real
            //   leak, not a side channel: 39 connections to chatgpt.com
            //   front-ends (rule host fail-closed) once egressed the primary in
            //   ~10 minutes through exactly this hole, because chatgpt's IPs are
            //   census-shared with direct hosts.
            //
            //   One carve-out: an address whose direct tenant a MAIN-route rule
            //   claims. Blocking it cannot divert that tenant into the tunnel —
            //   the user's own rule sends it the other way — so the block only
            //   kills it (google.com against a named `aistudio.google.com` on
            //   the shared front-end). Two rules of the user's own contradict
            //   each other on one address; honouring the main-route one costs a
            //   possible leak of the other while the link is down, and honouring
            //   the pin costs a dead site every second of the day. Strict mode
            //   keeps the pin-everything posture for anyone who wants the
            //   opposite trade.
            //
            // The smart PIN partition above stays smart in BOTH modes —
            // re-pinning shared IPs is what killed google.com in the 0719 run;
            // only the exemption subtraction tightens. A fake-IP transition
            // triggers an immediate replan (the settings write hook on
            // toggle/mode flips, the datapath watchdog on health flips), so
            // this gate is re-evaluated promptly, never left waiting for an
            // unrelated recompute.
            let never_exempt_secondary_ips: std::collections::HashSet<std::net::Ipv4Addr> =
                if fake_ip_name_enforcement_active {
                    ks_dest_ips.iter().copied().collect()
                } else if policy.kill_switch_strict_shared_ips {
                    codegen_out.secondary_dest_ips.iter().copied().collect()
                } else {
                    let main_route_claimed = self.fqdn_cache.shared_direct_ips_primary_ruled();
                    codegen_out
                        .secondary_dest_ips
                        .iter()
                        .copied()
                        .filter(|ip| !main_route_claimed.contains(ip))
                        .collect()
                };
            // known-primary destination IPs
            // that earn a packet-layer permit under a block-all so ping/ICMP to a
            // positively primary-routed host is not cut. Subtract the
            // never-exempt secondary set: while the secondary is down (the only
            // time the block-all arms) those IPs must stay blocked
            // (fail-closed), never rescued via the primary permit.
            let known_primary_dest_ips: Vec<std::net::Ipv4Addr> = codegen_out
                .primary_dest_ips
                .iter()
                .copied()
                .filter(|ip| !never_exempt_secondary_ips.contains(ip))
                .collect();
            match (self.kill_switch_resolver)(sid) {
                Some(resolution) => {
                    // Mode A (PreferPrimary) protects only the selected secondary
                    // destinations; mode B arms the catch-all (all off-tunnel).
                    let ks = match behavior_mode {
                        RouteBehaviorMode::PreferPrimary => {
                            let mut ks = crate::killswitch_codegen::kill_switch_filters(
                                sid,
                                &ks_dest_ips,
                                resolution.secondary_luid,
                                protocols,
                            );
                            //  — also pin secondary-routed apps to the
                            // secondary adapter egress (ALE layer only — no per-app ICMP).
                            ks.extend(crate::killswitch_codegen::app_kill_switch_filters(
                                sid,
                                &codegen_out.secondary_app_patterns,
                                resolution.secondary_luid,
                                protocols,
                            ));
                            ks
                        }
                        RouteBehaviorMode::PreferSecondaryWhenAvailable
                        | RouteBehaviorMode::StrictSecondaryFailClosed => {
                            crate::killswitch_codegen::catch_all_kill_switch_filters(
                                sid,
                                &resolution,
                                protocols,
                            )
                        }
                    };
                    if ks.is_empty() {
                        // Leak-proof pair could not arm — honour the failure
                        // posture instead of silently allowing.
                        if fail_closed {
                            // the non-PreferPrimary modes
                            // catch-all in `fail_closed_filters` regardless of
                            // the `block_all` flag below.
                            block_all_armed = behavior_mode != RouteBehaviorMode::PreferPrimary;
                            let exemptions = FailClosedExemptions {
                                bootstrap_server_ips: resolution.bootstrap_server_ips.clone(),
                                local_subnets: resolution.local_subnets.clone(),
                                // Inert here — this branch calls fail_closed_filters
                                // with block_all=false (per-IP path), which ignores
                                // primary_dest_ips; primary IPs are never blocked
                                // per-IP. Set for struct completeness only.
                                primary_dest_ips: known_primary_dest_ips.clone(),
                                // Secondary is UP here (this is the per-IP path,
                                // block_all=false below) — DNS-over-primary is a
                                // block-all-only relaxation, so never set here.
                                allow_dns_over_primary: false,
                                // per-IP path never blocks direct hosts,
                                // so there is nothing to exempt.
                                known_direct_ips: Vec::new(),
                                // Per-IP path never blocks the tunnel next-hop
                                // (only enumerated rule destinations), so the
                                // liveness probe needs no hole here.
                                probe_target_ips: Vec::new(),
                            };
                            // review fix — the secondary (VPN) is UP here
                            // (`Some`); `ks` is empty only because there is nothing
                            // to pin yet (cold FQDN cache for zone/suffix rules).
                            // Do NOT escalate to the catch-all block-all in this
                            // branch — that would cut ALL egress while the secondary adapter is
                            // healthy (and, with an off-subnet DNS, deadlock the
                            // cache warm-up so it never lifts). Keep the per-IP
                            // leak-guard (an empty dest set ⇒ a harmless no-op).
                            // The catch-all is reserved for the `None` branch,
                            // where the secondary is genuinely unresolved.
                            let fc = self.fail_closed_filters(
                                sid,
                                behavior_mode,
                                &ks_dest_ips,
                                &exemptions,
                                protocols,
                                false,
                            );
                            // full-level only on posture change;
                            // the ~5 s reconcile re-deriving the same state
                            // logs at debug (NDJSON flood → archive-cap burn).
                            if self.posture_changed(sid, "pair-empty-fail-closed") {
                                tracing::warn!(
                                    target: "nrr::per_sid_orchestrator",
                                    sid,
                                    mode = ?behavior_mode,
                                    fail_closed_filters = fc.len(),
                                    "kill-switch could not arm the leak-proof pair — FAIL-CLOSED (blocking)",
                                );
                            } else {
                                tracing::debug!(
                                    target: "nrr::per_sid_orchestrator",
                                    sid,
                                    mode = ?behavior_mode,
                                    fail_closed_filters = fc.len(),
                                    "kill-switch could not arm the leak-proof pair — FAIL-CLOSED (blocking)",
                                );
                            }
                            collect_block_ids(&fc, &mut killswitch_block_ids);
                            filters.extend(fc);
                            //  — this branch blocks too (per-IP in
                            // mode A, catch-all in mode B), so the VPN-client /
                            // primary-app exemptions must ride along, exactly
                            // as in the `None` (secondary-unresolved) branch
                            // below. Previously promised by the comment above
                            // `exempt_patterns` but never emitted here.
                            filters.extend(crate::killswitch_codegen::primary_app_exempt_filters(
                                sid,
                                &exempt_patterns,
                            ));
                        } else if self.posture_changed(sid, "pair-empty-fail-open") {
                            tracing::warn!(
                                target: "nrr::per_sid_orchestrator",
                                sid,
                                mode = ?behavior_mode,
                                "kill-switch requested but not armed this cycle (fail-open)",
                            );
                        } else {
                            tracing::debug!(
                                target: "nrr::per_sid_orchestrator",
                                sid,
                                mode = ?behavior_mode,
                                "kill-switch requested but not armed this cycle (fail-open)",
                            );
                        }
                    } else {
                        if self.posture_changed(sid, "active") {
                            tracing::info!(
                                target: "nrr::per_sid_orchestrator",
                                sid,
                                mode = ?behavior_mode,
                                kill_switch_filters = ks.len(),
                                "kill-switch active — pinned egress-conditional filters",
                            );
                        } else {
                            tracing::debug!(
                                target: "nrr::per_sid_orchestrator",
                                sid,
                                mode = ?behavior_mode,
                                kill_switch_filters = ks.len(),
                                "kill-switch active — pinned egress-conditional filters",
                            );
                        }
                        collect_block_ids(&ks, &mut killswitch_block_ids);
                        filters.extend(ks);
                        //  — the mode-B catch-all blocks EVERY
                        // off-tunnel flow while the tunnel is UP, and that
                        // includes the VPN client's own primary-side control
                        // traffic (server handshake, connectivity checks
                        // against ROTATING provider IPs — the hidemy.name 72 s
                        // hang-per-drop class). The client's egress IS the
                        // tunnel's transport, so the app exemption set is
                        // emitted here too — proactively, at arming — not only
                        // in the fail-closed branches below. Mode A is
                        // excluded: its armed set is per-destination pins, no
                        // catch-all, so an unconditional app permit would only
                        // weaken the pinned-destination guarantee.
                        if behavior_mode != RouteBehaviorMode::PreferPrimary {
                            filters.extend(crate::killswitch_codegen::primary_app_exempt_filters(
                                sid,
                                &exempt_patterns,
                            ));
                        }
                    }
                }
                None => {
                    // The secondary (VPN) interface could not be resolved at all.
                    if fail_closed {
                        let mut exemptions = (self.fail_closed_exemptions_resolver)(sid);
                        // opt-in: keep name resolution working over
                        // the primary link while the block-all is engaged (adds a
                        // port-scoped UDP/TCP-53 permit). Strict default = blocks DNS too.
                        exemptions.allow_dns_over_primary = policy.allow_dns_over_primary;
                        // known-primary hosts get a
                        // packet-layer permit so ping/ICMP to them survives the block-all
                        // (TCP/UDP already escapes at the ALE rule permit).
                        exemptions.primary_dest_ips = known_primary_dest_ips.clone();
                        // known-direct destinations (Mode-B steered
                        // answers + FCrDNS non-rule confirmations) get an ALE exempt +
                        // packet permit so plain primary-path sites survive the
                        // block-all. Subtract the never-exempt secondary set: while
                        // the secondary is down those IPs must stay blocked, never
                        // rescued via a direct-host permit (defense in depth — the
                        // provers already excluded pinned addresses). The base is
                        // two-mode (see `never_exempt_secondary_ips`): with fake-IP
                        // effective a census-shared IP the smart kill-switch declined
                        // to pin stays exemptible (its direct co-tenant remains
                        // reachable on the primary); with fake-IP off the strict base
                        // keeps it blocked — this exemption was the exact egress path
                        // of the  chatgpt.com leak.
                        if let Some(registry) = self.known_direct.as_ref() {
                            exemptions.known_direct_ips = registry
                                .snapshot()
                                .into_iter()
                                .filter(|ip| !never_exempt_secondary_ips.contains(ip))
                                .collect();
                        }
                        // a `FailClosedUnknown` Mode-A strategy
                        // escalates to the catch-all here (secondary unresolved) so a
                        // routed domain's un-seeded edge IP is blocked rather than
                        // leaked to the primary. `kill_switch_block_all` still forces
                        // it regardless of the strategy.
                        let effective_block_all =
                            policy.kill_switch_block_all || mode_a_fail_closed_unknown;
                        // the non-PreferPrimary modes catch-all
                        // in `fail_closed_filters` regardless of the flag.
                        block_all_armed = effective_block_all
                            || behavior_mode != RouteBehaviorMode::PreferPrimary;
                        let fc = self.fail_closed_filters(
                            sid,
                            behavior_mode,
                            &ks_dest_ips,
                            &exemptions,
                            protocols,
                            effective_block_all,
                        );
                        // Full-level only on a posture change or a heartbeat (the
                        // block-all/per-IP split is part of the posture, so a
                        // coverage escalation still re-logs immediately); steady
                        // ~5 s re-derivations in between drop to debug (this line
                        // alone fired 1000+ times in a single 26-minute block-all
                        // session — logging every one would burn the archive log
                        // cap, but a multi-minute block-all with zero warns after
                        // the opening line is not distinguishable from "silently
                        // stuck", hence the periodic heartbeat).
                        let posture = if effective_block_all {
                            "unresolved-fail-closed-block-all"
                        } else {
                            "unresolved-fail-closed-per-ip"
                        };
                        match self.posture_log_event(sid, posture) {
                            PostureLogEvent::Transition => {
                                tracing::warn!(
                                    target: "nrr::per_sid_orchestrator",
                                    sid,
                                    mode = ?behavior_mode,
                                    block_all = effective_block_all,
                                    mode_a_fail_closed_unknown,
                                    fail_closed_filters = fc.len(),
                                    "secondary interface unresolved — kill-switch FAIL-CLOSED (blocking)",
                                );
                            }
                            PostureLogEvent::Heartbeat { elapsed } => {
                                tracing::warn!(
                                    target: "nrr::per_sid_orchestrator",
                                    sid,
                                    mode = ?behavior_mode,
                                    block_all = effective_block_all,
                                    mode_a_fail_closed_unknown,
                                    fail_closed_filters = fc.len(),
                                    elapsed_minutes = elapsed.as_secs() / 60,
                                    "secondary interface still unresolved — kill-switch FAIL-CLOSED still blocking (heartbeat)",
                                );
                                // Announcing is not enough: after a resume the
                                // binding can stay unresolvable until something
                                // re-runs the name heal against live adapters.
                                if let Some(requests) = self.rebind_requests.as_ref() {
                                    requests.request("fail-closed-heartbeat");
                                }
                            }
                            PostureLogEvent::Steady => {
                                tracing::debug!(
                                    target: "nrr::per_sid_orchestrator",
                                    sid,
                                    mode = ?behavior_mode,
                                    block_all = effective_block_all,
                                    mode_a_fail_closed_unknown,
                                    fail_closed_filters = fc.len(),
                                    "secondary interface unresolved — kill-switch FAIL-CLOSED (blocking)",
                                );
                            }
                        }
                        collect_block_ids(&fc, &mut killswitch_block_ids);
                        filters.extend(fc);
                        // C4 — the secondary (VPN) is DOWN here, so a VPN client is
                        // bootstrapping over the primary; permit it through the block
                        // so the tunnel can establish (else fail-closed deadlocks it).
                        filters.extend(crate::killswitch_codegen::primary_app_exempt_filters(
                            sid,
                            &exempt_patterns,
                        ));
                    } else if self.posture_changed(sid, "unresolved-fail-open") {
                        tracing::warn!(
                            target: "nrr::per_sid_orchestrator",
                            sid,
                            "kill-switch requested but secondary interface unresolved — leaving it off (fail-open)",
                        );
                    } else {
                        tracing::debug!(
                            target: "nrr::per_sid_orchestrator",
                            sid,
                            "kill-switch requested but secondary interface unresolved — leaving it off (fail-open)",
                        );
                    }
                }
            }
        }
        // leak-guard disarmed ⇒ reset the posture latch so a
        // later re-arm logs at full level again (recorded silently).
        if !leak_guard_armed {
            let _ = self.posture_changed(sid, "off");
            // П0-A — nothing is pinned while disarmed, so no shared-IP
            // exclusions either; clear the GUI warning.
            if let Some(status) = self.shared_ip_exemption_status.as_ref() {
                status.set(&[]);
            }
        }
        // DoH/DoT lockdown. Independent of the kill-switch pins
        // above: block browser DNS-over-HTTPS to the resolver set (443/IP) + DNS-
        // over-TLS globally (853) so the observer sees plaintext DNS again (the
        // dzen.ru blind-spot class). Applied when enabled AND in scope — always,
        // or (the default) only while the kill-switch master toggle is on ("only
        // under leak protection"). The blocks sit in their own weight band above
        // rule permits but below the exemptions, so they never break the tunnel or
        // a primary-routed app. The resolver IPs are already resolved by the
        // composition root (host entries via the FQDN cache).
        if policy.doh_lockdown_enabled
            && (matches!(
                policy.doh_lockdown_scope,
                nrr_storage::doh_lockdown::DohLockdownScope::Always
            ) || policy.kill_switch_enabled)
        {
            let doh = crate::killswitch_codegen::doh_dot_block_filters(
                sid,
                &policy.doh_resolver_ips,
                true, // DoT (853) is a global block whenever the lockdown is active
            );
            if !doh.is_empty() {
                tracing::debug!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    doh_filters = doh.len(),
                    resolver_ips = policy.doh_resolver_ips.len(),
                    scope = policy.doh_lockdown_scope.as_slug(),
                    "DoH/DoT lockdown blocks emitted",
                );
                filters.extend(doh);
            }
        }
        // edge-triggered OS resolver-cache flush; a no-op
        // unless the block-all state changed since the previous compute.
        self.note_block_all_state(sid, block_all_armed);
        self.update_killswitch_registry(sid, killswitch_block_ids);
        Ok(ComputedFilterSet::Install(filters))
    }

    /// Convenience constructor with a no-op audit sink. Useful when
    /// the caller is wiring tests that care about install/remove
    /// behaviour but not audit ordering.
    pub fn with_noop_audit(
        session: Arc<WfpSession>,
        policy_source: Arc<dyn RoutePolicySource>,
        rules_provider: Arc<dyn RulesProvider>,
        fqdn_cache: Arc<dyn FqdnCacheLookup>,
    ) -> Self {
        Self::new(
            session,
            policy_source,
            rules_provider,
            fqdn_cache,
            Arc::new(NoopPerSidApplyAudit),
        )
    }

    /// Snapshot of the SIDs currently holding filter sets. Sorted for
    /// deterministic test assertions.
    pub fn installed_sids(&self) -> Vec<String> {
        let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<String> = g.keys().cloned().collect();
        out.sort();
        out
    }

    /// Number of WFP filter IDs installed for `sid`. Returns 0 if the
    /// SID has no entry.
    pub fn filter_count_for(&self, sid: &str) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|s| s.installed.len())
            .unwrap_or(0)
    }

    /// Install (or reinstall) the SID's filter set from the latest
    /// policy snapshot. Equivalent to a full
    /// `remove_for_sid` + `install_for_sid` cycle, modulo idempotent
    /// `WfpFilterAdd` (FWP_E_DUPLICATE_OBJECT → ignored).
    ///
    /// filters now come from the WFP codegen
    /// ([`crate::wfp_codegen::generate_filters`]) which iterates the
    /// active rule book × FQDN cache, not from a placeholder permit-
    /// per-binding shape. The per-SID `PerSidPolicySnapshot` is still
    /// loaded — its presence/absence governs whether the orchestrator
    /// processes the SID at all — but the bindings themselves drive
    /// the Windows routing table (block 16.12.A.4+), not the WFP
    /// filter list.
    /// confirm each id in
    /// `installed_ids` is actually live in WFP after an install. Missing ids
    /// are PHANTOMS (recorded installed but never materialised). Logs the
    /// outcome; returns `Some(phantom_count)` on a successful enumeration and
    /// `None` when the live filters could not be read (verification skipped).
    /// Best-effort — the production caller ignores the return (the check is a
    /// safety net, not a gate); the value exists so tests can assert on it.
    /// `expected` is the count we claimed installed.
    fn verify_installed_filters_live(
        &self,
        sid: &str,
        installed_ids: &[WfpFilterId],
        expected: usize,
    ) -> Option<usize> {
        if installed_ids.is_empty() {
            return Some(0);
        }
        match self.session.enumerate_our_filters() {
            Ok(live) => {
                let live_ids: std::collections::HashSet<u64> =
                    live.iter().map(|r| r.id.raw).collect();
                let phantom = installed_ids
                    .iter()
                    .filter(|id| !live_ids.contains(&id.raw))
                    .count();
                if phantom > 0 {
                    tracing::error!(
                        target: "nrr::per_sid_orchestrator",
                        sid,
                        phantom,
                        expected,
                        "verify-after-apply: filters recorded as installed are NOT live in WFP (phantom) — real enforcement is weaker than reported",
                    );
                } else {
                    tracing::debug!(
                        target: "nrr::per_sid_orchestrator",
                        sid,
                        verified = expected,
                        "verify-after-apply: every installed filter confirmed live in WFP",
                    );
                }
                Some(phantom)
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    "verify-after-apply: could not enumerate live WFP filters (skipping check): {e:?}",
                );
                None
            }
        }
    }

    pub fn install_for_sid(&self, sid: &str) -> Result<usize, OrchestratorError> {
        self.install_for_sid_with(sid, None)
    }

    /// [`Self::install_for_sid`] with an optional caller-supplied rules
    /// snapshot (block 16.HW-0716 P0.2 — see `compute_filters_for_sid`).
    fn install_for_sid_with(
        &self,
        sid: &str,
        rules_override: Option<&ActiveRulesSnapshot>,
    ) -> Result<usize, OrchestratorError> {
        if sid.is_empty() {
            return Err(OrchestratorError::EmptySid);
        }
        // the admin baseline is never enforced as its
        // own machine-wide filter set. It only ever reaches the wire as a
        // per-user read-through (a real `S-…` SID resolves the baseline
        // when it has no revision of its own). When NOBODY is logged in,
        // the active-SID set is empty, so `reconcile` installs nothing and
        // routing is passthrough — the baseline never gets a filter set of
        // its own. This guard makes that invariant explicit.
        if sid == nrr_domain::user_principal::BASELINE_PRINCIPAL {
            return Err(OrchestratorError::BaselineNotRoutable);
        }
        let was_known = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(sid);
        // Derive the full filter set (rule-driven + leak-guard) via the shared
        // `compute_filters_for_sid` path. No-policy / no-active-rules install
        // nothing but still record the SID so a later on_disconnect / recompile
        // stays consistent.
        let filters = match self.compute_filters_for_sid(sid, true, rules_override)? {
            ComputedFilterSet::NoPolicy => {
                // No policy → record the SID as known (so a later on_disconnect
                // doesn't panic) but install nothing.
                self.upsert_state(sid, Vec::new());
                self.emit_audit(sid, PerSidApplyAuditKind::Applied, 0, "no-policy");
                return Ok(0);
            }
            ComputedFilterSet::NoActiveRules => {
                self.upsert_state(sid, Vec::new());
                let kind = if was_known {
                    PerSidApplyAuditKind::Updated
                } else {
                    PerSidApplyAuditKind::Applied
                };
                self.emit_audit(sid, kind, 0, "no-active-rules");
                return Ok(0);
            }
            ComputedFilterSet::Install(f) => f,
        };
        // Route before block — same ordering invariant the reconcile enforces
        // (see `reconcile_to_desired`). A cold install lands the whole pin set
        // at once, so every destination it covers must already be routed.
        if let Some(route_sync) = self
            .route_sync
            .as_ref()
            .filter(|_| filters.iter().any(is_destination_block))
        {
            route_sync();
        }
        let actions: Vec<WfpFilterAction> = filters
            .iter()
            .cloned()
            .map(WfpFilterAction::AddFilter)
            .collect();
        let mode = (self.failure_mode)();
        let apply_outcome = match self.session.execute_wfp_plan_resilient(&actions, mode) {
            Ok(o) => o,
            Err(e) => {
                let msg = format!("install for {sid}: {e:?}");
                self.emit_audit(sid, PerSidApplyAuditKind::Failed, 0, &msg);
                return Err(OrchestratorError::WfpFailed(msg));
            }
        };
        // Record only the filters that actually installed — best-effort may
        // have skipped some un-materializable ones. Deleting a never-added
        // id later is idempotent, but tracking the real set keeps
        // `filter_count_for` honest.
        let skipped: std::collections::HashSet<u64> =
            apply_outcome.skipped.iter().map(|s| s.id.raw).collect();
        let installed_ids: Vec<WfpFilterId> = filters
            .iter()
            .map(|s| s.id)
            .filter(|id| !skipped.contains(&id.raw))
            .collect();
        let count = installed_ids.len();
        // re-read our LIVE WFP filters
        // and confirm every id we just recorded as installed is actually
        // present in the engine. A missing id = a PHANTOM: counted as installed
        // but never in WFP — the exact 0715 bug class (a mis-classified error
        // silently swallowed the add while `installed=N` still incremented). A
        // mismatch is logged LOUD (error) so a future regression is caught in
        // NDJSON instead of trusting `installed=N`. Best-effort: an enumeration
        // failure never fails the apply — verification is a safety net, not a
        // gate, and the filters are already committed by this point. Runs only
        // on a real install (this path), not on the frequent coverage-reconcile
        // tick, so the one extra enumeration per policy change is cheap.
        self.verify_installed_filters_live(sid, &installed_ids, count);
        // P3-followup — persist the ids so a hard-kill's orphans reap by id.
        if let Some(ledger) = self.ledger.as_ref() {
            ledger.record(&installed_ids);
        }
        self.upsert_state(sid, installed_ids);
        let kind = if was_known {
            PerSidApplyAuditKind::Updated
        } else {
            PerSidApplyAuditKind::Applied
        };
        if apply_outcome.skipped.is_empty() {
            // a clean install used to be audit-only; the 0716
            // run had to be diagnosed from the ABSENCE of log lines. Log success
            // at info so "did enforcement arm?" is answerable from NDJSON alone.
            tracing::info!(
                target: "nrr::per_sid_orchestrator",
                sid,
                installed = count,
                "per-SID WFP filter set installed",
            );
            self.emit_audit(sid, kind, count as u32, "ok");
        } else {
            let n = apply_outcome.skipped.len();
            tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                sid,
                installed = count,
                skipped = n,
                "per-SID apply completed best-effort — some rules were not enforceable on this host"
            );
            self.emit_audit(
                sid,
                kind,
                count as u32,
                &format!("ok ({n} rule(s) skipped — not enforceable on this host)"),
            );
        }
        Ok(count)
    }

    /// window-free, make-before-break reconcile of
    /// the per-SID filter set against the freshly-resolved secondary LUID.
    ///
    /// This both GROWS coverage additively (freshly-observed secondary IPs, the
    /// block 16.HW-0704 P1 case) AND reaps the tracked filters no longer desired
    /// — critically the **dead-LUID egress permits** left after a secondary adapter reconnect.
    /// (It replaces the earlier add-only `refresh_secondary_coverage`, which
    /// could grow but never reap.) The permit id
    /// now folds the LUID (see `killswitch_codegen::permit_luid_seg`), so a new
    /// LUID mints a new permit id; the stale old-LUID id is superseded and
    /// deleted here. (A WFP filter is immutable by key, so the new permit MUST
    /// be a new id — an add-only path would swallow the collision and the stale
    /// permit would stick, blocking legit secondary-adapter traffic until a policy recompile.)
    ///
    /// Ordering is strictly **ADD-then-DELETE** so the kill-switch is never
    /// briefly lifted. Across a **pure LUID flip** (reconnect) every BLOCK keeps
    /// a LUID-free stable id and stays in both the desired and tracked sets, so
    /// only the dead-LUID permits are deleted (deleting a permit only tightens —
    /// fail-safe). Across an **up↔down mode transition** a block's SHAPE changes
    /// (`block_off_secondary` ↔ `ale_block`, `catch_all_block` ↔ `ale_block`),
    /// so a superseded block CAN enter the delete set — there, safety rests on
    /// (a) add-before-delete installing the replacement block first, and (b) the
    /// delete pass being **deferred whenever a replacement BLOCK add was skipped**
    /// (best-effort), so a block is never removed while its replacement is not yet
    /// up. A skipped PERMIT does not defer the delete (skipping a permit only
    /// tightens), so a pure LUID flip still reaps the dead-LUID permits (gap #2)
    /// even if an app-permit is unmaterializable. The delete set is derived purely
    /// from the desired-vs-tracked id diff — never from stored metadata, which the
    /// untyped id set lacks.
    ///
    /// Correct across every secondary adapter transition (the diff drives it): reconnect
    /// (swap dead permit → live permit), up→down fail-closed (add block-all,
    /// then drop the per-dest set), up→down fail-open (drop the guard so traffic
    /// egresses the primary, the chosen posture), down→up (re-arm). A no-op
    /// (returns 0) when desired == tracked, so it is safe on every DNS-warmup /
    /// adapter / 30 s safety tick. Only acts on an already-installed SID (an
    /// inactive / not-yet-installed SID is owned by [`Self::reconcile`]).
    /// Returns the count of filters added.
    pub fn reconcile_secondary_coverage(&self, sid: &str) -> Result<usize, OrchestratorError> {
        // Snapshot the currently-tracked filters; skip SIDs we have not installed.
        let tracked: Vec<WfpFilterId> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match g.get(sid) {
                Some(s) => s.installed.clone(),
                None => return Ok(0),
            }
        };
        let desired = match self.compute_filters_for_sid(sid, false, None)? {
            ComputedFilterSet::Install(f) => f,
            // No policy / no active rules → nothing desired; leave the set as-is
            // (full teardown is owned by the stop / policy-change paths).
            ComputedFilterSet::NoPolicy | ComputedFilterSet::NoActiveRules => return Ok(0),
        };
        self.reconcile_to_desired(sid, tracked, desired, "LUID-aware permit refresh", false)
            .map(|(added, _live_total)| added)
    }

    /// The shared MAKE-then-BREAK core: bring the installed set for an
    /// already-tracked `sid` to exactly `desired`, without ever opening a
    /// window (adds land first; superseded filters are deleted after; an
    /// unchanged filter is never touched). Both the adapter-transition
    /// reconcile and the user-apply recompile funnel through here, so the
    /// leak-safety reasoning above is written once. `audit_note` labels the
    /// audit line with the caller's intent. Returns `(added, live_total)` —
    /// the adds this pass installed, and the tracked set size after the pass
    /// (the recompile path reports the latter to keep the historical
    /// "installed count" contract of the full replace it supersedes).
    /// `audit_no_op` audits even a no-change pass — a user Apply must leave a
    /// record, while the periodic reconcile tick must not spam one every 30 s.
    fn reconcile_to_desired(
        &self,
        sid: &str,
        tracked: Vec<WfpFilterId>,
        desired: Vec<WfpFilterSpec>,
        audit_note: &str,
        audit_no_op: bool,
    ) -> Result<(usize, usize), OrchestratorError> {
        let tracked_ids: std::collections::HashSet<u64> = tracked.iter().map(|id| id.raw).collect();
        let desired_ids: std::collections::HashSet<u64> =
            desired.iter().map(|s| s.id.raw).collect();

        let to_add: Vec<WfpFilterSpec> = desired
            .iter()
            .filter(|s| !tracked_ids.contains(&s.id.raw))
            .cloned()
            .collect();
        // Tracked ids no longer desired — the stale dead-LUID permits (and any
        // block-all superseded by a per-dest set on re-arm). Blocks keep stable
        // ids across a LUID flip, so they stay in `desired` and never appear here.
        let to_remove: Vec<WfpFilterId> = tracked
            .iter()
            .copied()
            .filter(|id| !desired_ids.contains(&id.raw))
            .collect();

        if to_add.is_empty() && to_remove.is_empty() {
            if audit_no_op {
                self.emit_audit(
                    sid,
                    PerSidApplyAuditKind::Updated,
                    0,
                    &format!("reconcile: +0 -0 ({audit_note})"),
                );
            }
            return Ok((0, tracked.len()));
        }

        // (0) ROUTE BEFORE BLOCK. A destination-scoped block only
        // tolerates traffic that egresses the secondary, and what puts a
        // destination on the secondary is its `/32` route. The route pass and
        // this filter pass read the same live FQDN / app-observation stores but
        // at different instants, so an address learned in between is pinned
        // here while the route pass that would have carried it has already run
        // — and every flow to it is dropped until the next route recompute.
        // Driving the route pass here, for NEW destination blocks only, closes
        // that window without ever lifting a block (this runs before the MAKE,
        // and the BREAK below is unchanged). No lock is held at this point.
        // Costs nothing in steady state: an unchanged coverage set adds no
        // destination block and never reaches this call.
        if let Some(route_sync) = self
            .route_sync
            .as_ref()
            .filter(|_| to_add.iter().any(is_destination_block))
        {
            route_sync();
        }

        // (1) MAKE: add the new filters FIRST — window-free (blocks untouched;
        // the new-LUID permit goes up before the stale one comes down).
        let mut installed_ids: Vec<WfpFilterId> = Vec::new();
        // Gates the delete pass below (leak-safety — see the BREAK comment).
        let mut block_replacement_skipped = false;
        if !to_add.is_empty() {
            let actions: Vec<WfpFilterAction> = to_add
                .iter()
                .cloned()
                .map(WfpFilterAction::AddFilter)
                .collect();
            let mode = (self.failure_mode)();
            let apply_outcome = match self.session.execute_wfp_plan_resilient(&actions, mode) {
                Ok(o) => o,
                Err(e) => {
                    let msg = format!("reconcile coverage for {sid}: {e:?}");
                    self.emit_audit(sid, PerSidApplyAuditKind::Failed, 0, &msg);
                    return Err(OrchestratorError::WfpFailed(msg));
                }
            };
            let skipped: std::collections::HashSet<u64> =
                apply_outcome.skipped.iter().map(|s| s.id.raw).collect();
            // A skipped PERMIT never uncovers a destination (skipping a permit
            // only tightens — the block half stays); only a skipped BLOCK can
            // leave a destination without a covering block. So the BREAK is
            // unsafe iff a *destination-covering* BLOCK add was skipped this tick.
            //
            // the gate previously armed on ANY skipped block, including
            // an app-scoped block (ALE app-id, no remote) whose exe did not
            // resolve (0x80320002). Such a block covers no destination IP, so
            // skipping it cannot uncover anything — yet when the exe is
            // *persistently* absent (e.g. 53 app rules for uninstalled apps on
            // the 0718 boot run) it re-armed the gate every 2 s tick, so the
            // superseded-PERMIT delete pass was deferred forever and the
            // over-coverage backlog grew without bound. Excluding app-only block
            // skips lets the stale permits reap while still deferring on a real
            // destination-block replacement miss (the actual leak case).
            block_replacement_skipped = to_add.iter().any(|s| {
                s.action == WfpAction::Block && skipped.contains(&s.id.raw) && !is_app_only_block(s)
            });
            installed_ids = to_add
                .iter()
                .map(|s| s.id)
                .filter(|id| !skipped.contains(&id.raw))
                .collect();
            if let Some(ledger) = self.ledger.as_ref() {
                ledger.record(&installed_ids);
            }
        }

        // (2) BREAK: delete the superseded filters by id — but defer when a BLOCK
        // replacement was skipped this tick. A pure LUID flip keeps every block id
        // stable, so `to_add` is permits-only and `to_remove` is just dead-LUID
        // permits (inert — deleting them only tightens); `block_replacement_
        // skipped` is false → the BREAK runs and gap #2 reaps the stale permits
        // EVEN when an app-permit is unmaterializable. But an up↔down mode
        // transition swaps a block's SHAPE (`block_off_secondary` ↔ `ale_block`,
        // `catch_all_block` ↔ `ale_block`, different ids), so a superseded BLOCK
        // can land in `to_remove`; if its replacement BLOCK's ADD was best-effort-
        // SKIPPED (e.g. a fail-closed app-block whose exe app-id did not resolve),
        // deleting the old block would UNCOVER the destination → leak. So when any
        // block add was skipped, defer the whole delete pass: harmless over-
        // coverage that the next tick reconciles once the block materialises.
        // Delete-missing is idempotent; the batch is best-effort.
        let removed: Vec<WfpFilterId> = if !to_remove.is_empty() && !block_replacement_skipped {
            let actions: Vec<WfpFilterAction> = to_remove
                .iter()
                .copied()
                .map(WfpFilterAction::DeleteFilter)
                .collect();
            if let Err(e) = self.session.execute_wfp_plan(&actions) {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    "reconcile coverage: delete of superseded filters best-effort failed: {e:?}",
                );
            }
            to_remove.clone()
        } else {
            if !to_remove.is_empty() {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    deferred = to_remove.len() as u64,
                    "reconcile coverage: deferred delete of superseded filters — a replacement block add was skipped this tick (fail-safe over-coverage; retry next tick)",
                );
            }
            Vec::new()
        };

        // (3) Update the tracked set = (tracked − removed) ∪ installed. `removed`
        // reflects what was actually deleted (empty when the delete was deferred),
        // so deferred ids stay tracked and are retried on the next tick.
        let live_total = {
            let removed_ids: std::collections::HashSet<u64> =
                removed.iter().map(|id| id.raw).collect();
            let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let entry = g.entry(sid.to_string()).or_insert_with(|| PerSidFilterSet {
                sid: sid.to_string(),
                installed: Vec::new(),
            });
            entry.installed.retain(|id| !removed_ids.contains(&id.raw));
            let mut have: std::collections::HashSet<u64> =
                entry.installed.iter().map(|id| id.raw).collect();
            for id in installed_ids.iter().copied() {
                if have.insert(id.raw) {
                    entry.installed.push(id);
                }
            }
            entry.installed.len()
        };

        let added = installed_ids.len();
        let removed_count = removed.len();
        self.emit_audit(
            sid,
            PerSidApplyAuditKind::Updated,
            added as u32,
            &format!("reconcile: +{added} -{removed_count} ({audit_note})"),
        );
        Ok((added, live_total))
    }

    /// Remove every filter the orchestrator previously installed for
    /// `sid`. Idempotent on unknown SIDs.
    pub fn remove_for_sid(&self, sid: &str) -> Result<usize, OrchestratorError> {
        if sid.is_empty() {
            return Err(OrchestratorError::EmptySid);
        }
        let installed = {
            let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.remove(sid).map(|s| s.installed).unwrap_or_default()
        };
        // a removed set can no longer be blocking; reset the
        // latch so a later re-arm is a real edge (fires the flush again).
        self.note_block_all_state(sid, false);
        if installed.is_empty() {
            return Ok(0);
        }
        let actions: Vec<WfpFilterAction> = installed
            .iter()
            .copied()
            .map(WfpFilterAction::DeleteFilter)
            .collect();
        let count = actions.len();
        if let Err(e) = self.session.execute_wfp_plan(&actions) {
            let msg = format!("remove for {sid}: {e:?}");
            self.emit_audit(sid, PerSidApplyAuditKind::Failed, count as u32, &msg);
            return Err(OrchestratorError::WfpFailed(msg));
        }
        self.emit_audit(sid, PerSidApplyAuditKind::Withdrawn, count as u32, "ok");
        Ok(count)
    }

    /// Strip **every** WFP filter the service owns (block AND permit, all
    /// SIDs). Used by the graceful-stop teardown hook. Also clears the
    /// in-memory SID→filter map so a subsequent reconcile reinstalls from a
    /// clean slate. Idempotent — a second call deletes nothing.
    ///
    /// two-pass, robust against an enumerate that
    /// under-reports (the `stripped_filters:0` HW anomaly): (1) delete every
    /// filter we KNOW we installed this session **by id** (`FwpmFilterDeleteBy
    /// Key0` does not depend on enumeration, so a graceful stop can never leave
    /// an orphaned block = lockout for this process's filters); (2) enumerate-
    /// sweep for anything untracked (cross-session orphans from a prior
    /// hard-killed instance whose in-memory state is gone). The WFP session is
    /// **non-dynamic** — filters persist until an explicit delete or reboot —
    /// so this explicit strip (not session close) is what removes them.
    pub fn cleanup_wfp(&self) -> Result<usize, OrchestratorError> {
        // (1) Delete this session's known filters by id.
        let tracked: Vec<WfpFilterId> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.values()
                .flat_map(|s| s.installed.iter().copied())
                .collect()
        };
        let tracked_deleted = tracked.len();
        if !tracked.is_empty() {
            let actions: Vec<WfpFilterAction> = tracked
                .into_iter()
                .map(WfpFilterAction::DeleteFilter)
                .collect();
            // Delete-missing is idempotent (FWP_E_FILTER_NOT_FOUND → ok).
            if let Err(e) = self.session.execute_wfp_plan(&actions) {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    "cleanup_wfp: delete-by-tracked-id best-effort failed: {e:?}",
                );
            }
        }
        // (2) Enumerate-sweep for untracked orphans.
        let swept = self
            .session
            .cleanup_all()
            .map_err(|e| OrchestratorError::WfpFailed(format!("cleanup_all: {e:?}")))?;
        self.state.lock().unwrap_or_else(|p| p.into_inner()).clear();
        // every set is gone; reset the block-all latches so a
        // post-cleanup re-arm is a real edge. (No flush here — teardown itself
        // unblocks nothing the OS cache could hide.)
        self.block_all_flush_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        // P3-followup — filters are gone; drop the on-disk ledger so the next
        // start has no orphans to reap.
        if let Some(ledger) = self.ledger.as_ref() {
            ledger.clear();
        }
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            tracked_deleted,
            swept,
            "cleanup_wfp: stripped all NRR WFP filters (tracked ids + enumerated sweep)",
        );
        Ok(tracked_deleted + swept)
    }

    /// reap a hard-killed PRIOR instance's
    /// orphaned filters at startup. Reads the on-disk ledger (ids the dead
    /// process recorded before it was killed) and deletes each **by id** — no
    /// dependence on `wfp_enumerate_our_filters`, so it works even when
    /// enumerate under-reports (the `stripped_filters:0` anomaly). Idempotent
    /// (delete-missing is a no-op). Drains + truncates the ledger. Returns the
    /// number of ids reaped. No-op (returns 0) when no ledger is wired.
    pub fn cleanup_persisted_orphans(&self) -> usize {
        let Some(ledger) = self.ledger.as_ref() else {
            return 0;
        };
        let ids = ledger.drain();
        if ids.is_empty() {
            return 0;
        }
        let actions: Vec<WfpFilterAction> = ids
            .iter()
            .map(|raw| WfpFilterAction::DeleteFilter(WfpFilterId { raw: *raw }))
            .collect();
        if let Err(e) = self.session.execute_wfp_plan(&actions) {
            tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                "cleanup_persisted_orphans: delete-by-id best-effort failed: {e:?}",
            );
        } else {
            tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                reaped = ids.len() as u64,
                "startup: reaped hard-killed prior instance's WFP filters by persisted id",
            );
        }
        ids.len()
    }

    /// Strip only **block** (kill-switch / fail-closed) WFP filters, keeping
    /// permit filters. Used on `routing_stop_policy = persist` graceful stop
    /// (matched hosts keep egressing the secondary, but no block ever
    /// persists) and — unconditionally — at service startup so an orphaned
    /// kill-switch left by a hard-killed prior instance can never lock the
    /// user out. Leaves the in-memory SID→filter map untouched: any now-gone
    /// block IDs it still references are handled idempotently on the next
    /// `remove_for_sid` (delete-missing → success).
    pub fn cleanup_wfp_blocks_only(&self) -> Result<usize, OrchestratorError> {
        self.session
            .cleanup_blocks_only()
            .map_err(|e| OrchestratorError::WfpFailed(format!("cleanup_blocks_only: {e:?}")))
    }

    /// Recompile the filter set for `sid` after a policy/rules change. Called
    /// when a user submits `RoutePolicyUpdate` so their new bindings take
    /// effect immediately.
    ///
    /// Window-free: the original remove-then-install replace
    /// opened a measured 1.4–5.8 s hole with NO NetRuleRouter filter installed
    /// — three of those applies ran while the secondary was down, so protected
    /// destinations were reachable off-tunnel for the whole hole. An
    /// already-installed SID now takes the same MAKE-then-BREAK diff the
    /// adapter-transition reconcile uses ([`Self::reconcile_to_desired`]):
    /// adds land first, superseded filters are deleted after, unchanged
    /// filters are never touched. A never-installed SID takes the plain
    /// install path (nothing is up — no window to close), and a SID whose
    /// policy/rules disappeared tears down via the full-replace path so the
    /// empty state and its audits stay exactly as before.
    pub fn recompile_for_sid(&self, sid: &str) -> Result<usize, OrchestratorError> {
        self.recompile_for_sid_impl(sid, None)
    }

    /// full recompile with the rules supplied by the
    /// caller instead of a storage read. The activation coordinator dispatches
    /// apply BEFORE committing the active-revision pointer (all-or-nothing:
    /// revert must stay possible), so `recompile_for_sid` at activation time
    /// still saw the PREVIOUS revision — the 0716 run applied
    /// "no-active-rules" at the exact activation moment and the new rules only
    /// reached WFP via the next 30 s safety tick. Window-free like
    /// [`Self::recompile_for_sid`].
    pub fn recompile_for_sid_with_rules(
        &self,
        sid: &str,
        rules: &ActiveRulesSnapshot,
    ) -> Result<usize, OrchestratorError> {
        self.recompile_for_sid_impl(sid, Some(rules))
    }

    fn recompile_for_sid_impl(
        &self,
        sid: &str,
        rules_override: Option<&ActiveRulesSnapshot>,
    ) -> Result<usize, OrchestratorError> {
        if sid.is_empty() {
            return Err(OrchestratorError::EmptySid);
        }
        let tracked: Option<Vec<WfpFilterId>> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.get(sid).map(|s| s.installed.clone())
        };
        // Never installed → nothing is up, so plain install opens no window.
        let Some(tracked) = tracked else {
            return self.install_for_sid_with(sid, rules_override);
        };
        match self.compute_filters_for_sid(sid, true, rules_override)? {
            // Policy/rules gone → a real teardown; the full-replace path
            // re-records the empty state and emits the same audits as before.
            ComputedFilterSet::NoPolicy | ComputedFilterSet::NoActiveRules => {
                let _ = self.remove_for_sid(sid)?;
                self.install_for_sid_with(sid, rules_override)
            }
            ComputedFilterSet::Install(desired) => self
                .reconcile_to_desired(sid, tracked, desired, "window-free recompile", true)
                .map(|(_added, live_total)| live_total),
        }
    }

    fn emit_audit(&self, sid: &str, kind: PerSidApplyAuditKind, filter_count: u32, message: &str) {
        self.audit.emit(PerSidApplyAuditRecord {
            sid: sid.to_string(),
            kind,
            filter_count,
            message: message.to_string(),
        });
    }

    /// Reconcile orchestrator state with the active set. Called by the
    /// `ActiveSidRegistry` membership-change listener.
    /// - SIDs in `snapshot` but not yet installed → `install_for_sid`.
    /// - SIDs installed but not in `snapshot` → `remove_for_sid`.
    /// - SIDs in both → unchanged.
    ///
    /// Errors are accumulated; the first error stops reconciliation
    /// for the remaining SIDs but already-applied changes are kept
    /// (consistent with the WFP transactions inside install/remove).
    pub fn reconcile(&self, snapshot: &[String]) -> Result<(), OrchestratorError> {
        let want: std::collections::BTreeSet<String> = snapshot.iter().cloned().collect();
        let have: std::collections::BTreeSet<String> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.keys().cloned().collect()
        };
        for sid in want.difference(&have) {
            self.install_for_sid(sid)?;
        }
        for sid in have.difference(&want) {
            self.remove_for_sid(sid)?;
        }
        Ok(())
    }

    fn upsert_state(&self, sid: &str, installed: Vec<WfpFilterId>) {
        let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        g.insert(
            sid.to_string(),
            PerSidFilterSet {
                sid: sid.to_string(),
                installed,
            },
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // a leak-guard-ARMED SID whose secondary is unresolved (the `None`
    // fail-closed branch = VPN down) also gets the built-in VPN-client exemption
    // permits so a VPN can bootstrap through the block. Fixtures built with
    // `snap_full` (secondary bound + kill-switch enabled) hit that path.
    //
    // those exemptions are now the built-in globs RESOLVED
    // to on-disk exe paths via the orchestrator's `AppPathResolver`. These fixtures
    // wire no resolver, so the default `NoopAppPathResolver` resolves every built-in
    // glob to nothing → ZERO exempt permits. Hence EXEMPT = 0 here. The resolution
    // path (a real path yields a real permit, a glob never leaks) has dedicated
    // coverage in `builtin_vpn_globs_resolve_to_paths_no_glob_in_fail_closed_set`.
    const EXEMPT: usize = 0;

    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::RuleId;
    use nrr_platform_api::types::WfpAction;
    use nrr_platform_api::windows_api::{MockWindowsApi, WindowsApiPort};

    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;

    /// Trivial scripted `RoutePolicySource` for tests.
    #[derive(Default)]
    struct ScriptedSource {
        per_sid: Mutex<HashMap<String, PerSidPolicySnapshot>>,
    }
    impl ScriptedSource {
        fn set(&self, sid: &str, snap: PerSidPolicySnapshot) {
            self.per_sid.lock().unwrap().insert(sid.to_string(), snap);
        }
    }
    impl RoutePolicySource for ScriptedSource {
        fn load_for_sid(&self, sid: &str) -> Option<PerSidPolicySnapshot> {
            self.per_sid.lock().unwrap().get(sid).cloned()
        }
    }

    /// Scripted `RulesProvider` for tests. Holds an `Option` so tests
    /// can flip between "no active rules" and "rules X". `set_*`
    /// helpers below construct test rule books that produce the
    /// filter counts each test asserts on.
    #[derive(Default)]
    struct ScriptedRules {
        snapshot: Mutex<Option<ActiveRulesSnapshot>>,
    }
    impl ScriptedRules {
        fn set(&self, snap: ActiveRulesSnapshot) {
            *self.snapshot.lock().unwrap() = Some(snap);
        }
        #[allow(dead_code)]
        fn clear(&self) {
            *self.snapshot.lock().unwrap() = None;
        }
    }
    impl RulesProvider for ScriptedRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            self.snapshot.lock().unwrap().clone()
        }
    }

    /// Build a rule book with `n` ExactIp rules in the primary set
    /// and 0 in the secondary set. Each rule pins a distinct IPv4 so
    /// the codegen emits exactly `n` filters per SID under `PreferPrimary`
    /// mode.
    fn rules_with_n_primary_ips(n: u8) -> ActiveRulesSnapshot {
        let primary: Vec<CanonicalRule> = (0..n)
            .map(|i| CanonicalRule {
                id: RuleId(format!("r-{i}")),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(Ipv4Addr::new(10, 0, 0, i))),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            })
            .collect();
        ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(primary),
                secondary: CanonicalRuleSet::default(),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        }
    }

    fn snap_full(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
        PerSidPolicySnapshot {
            primary: Some(PerSidBinding {
                stable_id: primary.into(),
                display_name: String::new(),
                user_confirmed: true,
                known_stable_ids: Vec::new(),
            }),
            secondary: Some(PerSidBinding {
                stable_id: secondary.into(),
                display_name: String::new(),
                user_confirmed: true,
                known_stable_ids: Vec::new(),
            }),
            mode: PerSidBehaviorMode::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            // these fixtures drive the existing kill-switch behaviour
            // tests, which assert the ARMED leak-guard path; keep the master
            // toggle ON so those expectations hold under the new opt-in gate.
            kill_switch_enabled: true,
            allow_dns_over_primary: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            kill_switch_strict_shared_ips: true,
            // Pinned to the per-IP path these fixtures were written for. This is
            // once again the product default (HW-0718 flip); the FailClosedUnknown
            // escalation has its own dedicated tests.
            mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::PerIp,
            link_provider_exe_paths: Vec::new(),
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            doh_resolver_ips: Vec::new(),
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
        }
    }

    fn snap_primary_only(primary: &str) -> PerSidPolicySnapshot {
        PerSidPolicySnapshot {
            primary: Some(PerSidBinding {
                stable_id: primary.into(),
                display_name: String::new(),
                user_confirmed: false,
                known_stable_ids: Vec::new(),
            }),
            secondary: None,
            mode: PerSidBehaviorMode::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: true,
            allow_dns_over_primary: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            kill_switch_strict_shared_ips: true,
            // Pinned per-IP for the same reason as `snap_full` above (HW-0714).
            mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::PerIp,
            link_provider_exe_paths: Vec::new(),
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            doh_resolver_ips: Vec::new(),
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
        }
    }

    /// Audit collector for tests. Records every `emit` call.
    #[derive(Default)]
    struct CollectAudit {
        records: Mutex<Vec<PerSidApplyAuditRecord>>,
    }
    impl CollectAudit {
        fn snapshot(&self) -> Vec<PerSidApplyAuditRecord> {
            self.records.lock().unwrap().clone()
        }
    }
    impl PerSidApplyAudit for CollectAudit {
        fn emit(&self, record: PerSidApplyAuditRecord) {
            self.records.lock().unwrap().push(record);
        }
    }

    /// Shared fixture: orchestrator wired with the scripted
    /// policy/rules sources and an empty FQDN cache. By default the
    /// rules snapshot is seeded with **two** ExactIp rules so
    /// `install_for_sid` produces 2 filters per SID — matching the
    /// pre-16.12.A.3 placeholder count and letting most lifecycle
    /// tests keep their `len() == 2` assertions. Tests that need a
    /// different filter count call `rules.set(rules_with_n_primary_ips(n))`
    /// themselves.
    #[allow(clippy::type_complexity)]
    fn fixture() -> (
        Arc<MockWindowsApi>,
        Arc<PerSidApplyOrchestrator>,
        Arc<ScriptedSource>,
        Arc<ScriptedRules>,
        Arc<CollectAudit>,
    ) {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        rules.set(rules_with_n_primary_ips(2));
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let orch = Arc::new(PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        ));
        (api, orch, source, rules, audit)
    }

    /// Build a rule book with a single `Application` rule whose pattern is
    /// `app_name` and no address match. Under the default
    /// `NoopAppPathResolver` the exe resolves to nothing, so the codegen
    /// records an `AppUnresolved` diagnostic.
    fn rules_with_one_app(app_name: &str) -> ActiveRulesSnapshot {
        let rule = CanonicalRule {
            id: RuleId("app-1".into()),
            enabled: true,
            address_match: None,
            app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
                pattern: nrr_domain::canonical::CanonicalAppPattern::Exact(app_name.to_string()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        };
        ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![rule]),
                secondary: CanonicalRuleSet::default(),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        }
    }

    #[test]
    fn compute_records_unresolved_app_rules_into_status() {
        // an app rule whose exe resolves to no path (the
        // default NoopAppPathResolver) must publish the app pattern into the
        // shared `AppEnforcementStatus` for the GUI banner, while still
        // computing a (possibly empty) filter set.
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        source.set("S-1-5-21-APP", snap_primary_only("Wi-Fi"));
        let rules = Arc::new(ScriptedRules::default());
        rules.set(rules_with_one_app("vk.exe"));
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let status = crate::app_enforcement_status::AppEnforcementStatus::new();
        let orch = PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_app_enforcement_status(status.clone());

        // Empty before any compute.
        assert!(status.unresolved().is_empty());

        orch.compute_filters_for_sid("S-1-5-21-APP", true, None)
            .unwrap();

        assert_eq!(status.unresolved(), vec!["vk.exe".to_string()]);
    }

    #[test]
    fn doh_lockdown_emits_blocks_when_enabled_and_in_scope() {
        use nrr_storage::doh_lockdown::DohLockdownScope;
        let build = |scope: DohLockdownScope, kill_switch: bool| {
            let api = Arc::new(MockWindowsApi::new());
            let session =
                Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
            let source = Arc::new(ScriptedSource::default());
            let mut snap = snap_primary_only("Wi-Fi");
            snap.doh_lockdown_enabled = true;
            snap.doh_lockdown_scope = scope;
            snap.kill_switch_enabled = kill_switch;
            snap.doh_resolver_ips = vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)];
            source.set("S-1-5-21-DOH", snap);
            let rules = Arc::new(ScriptedRules::default());
            rules.set(rules_with_n_primary_ips(1));
            let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
            let audit = Arc::new(CollectAudit::default());
            let orch = PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            );
            let set = orch
                .compute_filters_for_sid("S-1-5-21-DOH", false, None)
                .unwrap();
            let filters = match set {
                ComputedFilterSet::Install(f) => f,
                _ => panic!("expected Install filter set"),
            };
            filters
                .iter()
                .filter(|f| f.remote_port == Some(443) || f.remote_port == Some(853))
                .count()
        };
        // Always scope → blocks regardless of the kill-switch: 2 IPs × (443 TCP+UDP)
        // + DoT (853 TCP+UDP) = 6.
        assert_eq!(build(DohLockdownScope::Always, false), 6);
        // Leak-protection-only + kill-switch ON → applies.
        assert_eq!(build(DohLockdownScope::LeakProtectionOnly, true), 6);
        // Leak-protection-only + kill-switch OFF → does NOT apply.
        assert_eq!(build(DohLockdownScope::LeakProtectionOnly, false), 0);
    }

    #[test]
    fn install_for_sid_with_no_policy_records_empty_state() {
        let (api, orch, _src, _rules, _audit) = fixture();
        let count = orch.install_for_sid("S-1-5-21-X").unwrap();
        assert_eq!(count, 0);
        assert_eq!(orch.installed_sids(), vec!["S-1-5-21-X".to_string()]);
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);
    }

    #[test]
    fn install_for_sid_refuses_the_baseline_principal() {
        // the baseline is a per-user default, never a
        // routable per-SID target of its own. Refused with no side effects.
        let (api, orch, src, _rules, _audit) = fixture();
        src.set(
            nrr_domain::user_principal::BASELINE_PRINCIPAL,
            snap_full("Wi-Fi", "TAP"),
        );
        let err = orch
            .install_for_sid(nrr_domain::user_principal::BASELINE_PRINCIPAL)
            .expect_err("baseline must not be routable");
        assert!(matches!(err, OrchestratorError::BaselineNotRoutable));
        assert!(orch.installed_sids().is_empty());
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    #[test]
    fn m1_no_active_user_means_no_enforcement_and_no_baseline_floor() {
        // when nobody is logged in the active-SID set
        // is empty: nothing is installed (routing is passthrough), and the
        // baseline is NOT applied as a machine-wide floor.
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

        // Empty active set on a fresh orchestrator → nothing installed.
        orch.reconcile(&[]).unwrap();
        assert!(orch.installed_sids().is_empty());
        assert!(api.wfp_filters.lock().unwrap().is_empty());

        // A user's tray connects → their filters appear.
        orch.reconcile(&["S-1-5-21-A".to_string()]).unwrap();
        assert_eq!(orch.installed_sids(), vec!["S-1-5-21-A".to_string()]);
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);

        // Everyone logs off (empty set again) → filters torn down; no
        // baseline floor is left enforcing on the wire.
        orch.reconcile(&[]).unwrap();
        assert!(orch.installed_sids().is_empty());
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    #[test]
    fn install_for_sid_with_policy_pushes_filters_to_wfp() {
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));
        let count = orch.install_for_sid("S-1-5-21-A").unwrap();
        assert_eq!(count, 2 + EXEMPT);
        let filters = api.wfp_filters.lock().unwrap();
        assert_eq!(filters.len(), 2 + EXEMPT);
        assert!(filters
            .iter()
            .all(|f| f.user_sid.as_deref() == Some("S-1-5-21-A")));
    }

    // ── WFP cleanup (persist-on-stop feature) ───────────────────────────────

    /// Build an orchestrator that shares `session` with the caller so a test
    /// can seed the live WFP table directly (as an orphaned prior instance
    /// would leave it) and then exercise the cleanup entrypoints.
    fn orch_sharing_session(session: Arc<WfpSession>) -> Arc<PerSidApplyOrchestrator> {
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        Arc::new(PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        ))
    }

    fn seeded_block_permit_block(session: &WfpSession, api: &MockWindowsApi) {
        let block = |raw: u64| WfpFilterSpec {
            layer: nrr_platform_api::types::WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: Some(Ipv4Addr::new(9, 9, 9, raw as u8)),
            remote_port: None,
            weight: 0x10_0000 + raw,
            id: WfpFilterId { raw },
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        };
        let permit = |raw: u64| WfpFilterSpec {
            action: WfpAction::Permit,
            ..block(raw)
        };
        session
            .execute_wfp_plan(&[
                WfpFilterAction::AddFilter(block(1)),
                WfpFilterAction::AddFilter(permit(2)),
                WfpFilterAction::AddFilter(block(3)),
            ])
            .unwrap();
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
    }

    #[test]
    fn cleanup_wfp_blocks_only_strips_blocks_and_keeps_permits() {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let orch = orch_sharing_session(Arc::clone(&session));
        seeded_block_permit_block(&session, &api);

        let removed = orch.cleanup_wfp_blocks_only().unwrap();
        assert_eq!(removed, 2, "only the two block filters must be stripped");
        let remaining = api.wfp_filters.lock().unwrap().clone();
        assert_eq!(remaining.len(), 1, "the permit filter must survive");
        assert_eq!(remaining[0].action, WfpAction::Permit);
    }

    #[test]
    fn cleanup_wfp_strips_all_filters_and_clears_state() {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let orch = orch_sharing_session(Arc::clone(&session));
        seeded_block_permit_block(&session, &api);

        let removed = orch.cleanup_wfp().unwrap();
        assert_eq!(removed, 3, "cleanup_wfp strips block AND permit filters");
        assert!(api.wfp_filters.lock().unwrap().is_empty());
        assert!(
            orch.installed_sids().is_empty(),
            "cleanup_wfp must clear the in-memory SID→filter map"
        );
    }

    // ── Kill-switch (block 16.18.vpn slice D) ───────────────────────────────

    const KS_LUID: u64 = 0xABCD_0000_0000_0001;

    /// Orchestrator wired with a scripted kill-switch resolver carrying
    /// just a LUID (no exemptions), so the per-destination (mode A)
    /// kill-switch path can be exercised deterministically.
    #[allow(clippy::type_complexity)]
    fn fixture_with_luid(
        luid: Option<u64>,
    ) -> (
        Arc<MockWindowsApi>,
        Arc<PerSidApplyOrchestrator>,
        Arc<ScriptedSource>,
        Arc<ScriptedRules>,
    ) {
        fixture_with_resolution(luid.map(|l| KillSwitchResolution {
            secondary_luid: l,
            ..Default::default()
        }))
    }

    /// Orchestrator wired with a scripted kill-switch resolution (full
    /// control over LUID + exemptions for catch-all / mode-B tests).
    #[allow(clippy::type_complexity)]
    fn fixture_with_resolution(
        resolution: Option<KillSwitchResolution>,
    ) -> (
        Arc<MockWindowsApi>,
        Arc<PerSidApplyOrchestrator>,
        Arc<ScriptedSource>,
        Arc<ScriptedRules>,
    ) {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_kill_switch_resolver(Arc::new(move |_| resolution.clone())),
        );
        (api, orch, source, rules)
    }

    /// Same as [`fixture_with_resolution`], plus a wired kill-switch drop
    /// registry, for tests that verify the reactive VPN-endpoint learner's
    /// registry publish.
    #[allow(clippy::type_complexity)]
    fn fixture_with_resolution_and_registry(
        resolution: Option<KillSwitchResolution>,
    ) -> (
        Arc<MockWindowsApi>,
        Arc<PerSidApplyOrchestrator>,
        Arc<ScriptedSource>,
        Arc<ScriptedRules>,
        Arc<crate::killswitch_drop_registry::KillswitchBlockFilterRegistry>,
    ) {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let registry =
            Arc::new(crate::killswitch_drop_registry::KillswitchBlockFilterRegistry::new());
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
            .with_killswitch_drop_registry(Arc::clone(&registry)),
        );
        (api, orch, source, rules, registry)
    }

    /// One secondary ExactIp rule → exactly one secondary destination
    /// for the kill-switch to protect.
    /// A primary-route ExactIp rule (16.HW-0716 P1b test helper).
    fn primary_ip_rule(id: &str, ip: Ipv4Addr) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(ip)),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn rules_with_secondary_ip(ip: Ipv4Addr) -> ActiveRulesSnapshot {
        ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::default(),
                secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                    id: RuleId("r-sec".into()),
                    enabled: true,
                    address_match: Some(CanonicalAddressMatch::ExactIp(ip)),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_domain::RuleAction::Route,
                    origin: None,
                }]),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        }
    }

    fn snap_block(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
        let mut s = snap_full(primary, secondary);
        s.block_secondary_when_unavailable = true;
        s
    }

    /// Kill-switch on, but posture set to fail-OPEN (legacy behaviour:
    /// allow + warn when the secondary can't be resolved).
    fn snap_block_fail_open(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
        let mut s = snap_block(primary, secondary);
        s.kill_switch_fail_closed = false;
        s
    }

    fn snap_block_mode_b(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
        let mut s = snap_block(primary, secondary);
        s.mode = PerSidBehaviorMode::PreferSecondaryWhenAvailable;
        s
    }

    fn full_ks_resolution() -> KillSwitchResolution {
        KillSwitchResolution {
            secondary_luid: KS_LUID,
            bootstrap_server_ips: vec![Ipv4Addr::new(203, 0, 113, 7)],
            local_subnets: vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
        }
    }

    #[test]
    fn mode_b_arms_catch_all_kill_switch() {
        let (api, orch, src, rules) = fixture_with_resolution(Some(full_ks_resolution()));
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
        src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        // 0704 (P2): the catch-all arms at BOTH the ALE (TCP/UDP) and the
        // packet layers. 16.HW-0716: the packet side is one NAMED block per
        // ICMP/IGMP/GRE/ESP (4) instead of one agnostic block-all; IPv6 adds a
        // V6 ALE + V6 packet block-all → 1 + 4 + 2 = 7 block filters.
        assert_eq!(
            filters
                .iter()
                .filter(|f| f.action == WfpAction::Block)
                .count(),
            7,
            "mode B: V4 ALE block + 4 named V4 packet blocks + V6 ALE + V6 packet"
        );
        assert_eq!(
            filters
                .iter()
                .filter(|f| f.local_interface_luid == Some(KS_LUID))
                .count(),
            2,
            "egress-via-secondary exemption present at both layers"
        );
        assert!(
            filters.iter().filter(|f| f.remote_subnet.is_some()).count() >= 3,
            "loopback + link-local + LAN subnet exemptions present"
        );
    }

    #[test]
    fn killswitch_registry_publishes_exactly_the_armed_block_ids() {
        let (api, orch, src, rules, registry) =
            fixture_with_resolution_and_registry(Some(full_ks_resolution()));
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
        src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        let block_ids: Vec<u64> = filters
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .map(|f| f.id.raw)
            .collect();
        assert!(!block_ids.is_empty());
        for id in &block_ids {
            assert!(
                registry.contains(*id),
                "every armed kill-switch/fail-closed Block id must be published",
            );
        }
        // Nothing outside the armed set is falsely reported as ours.
        assert!(!registry.contains(u64::MAX));
    }

    #[test]
    fn killswitch_registry_clears_when_leak_guard_disarms() {
        let (api, orch, src, rules, registry) =
            fixture_with_resolution_and_registry(Some(full_ks_resolution()));
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
        src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));
        orch.install_for_sid("S-1-5-21-A").unwrap();
        let armed_ids: Vec<u64> = api
            .wfp_filters
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .map(|f| f.id.raw)
            .collect();
        assert!(!armed_ids.is_empty());

        // Active rules withdrawn (e.g. the revision was cleared) → the
        // compute takes the `NoActiveRules` path, which must retract this
        // SID's entry rather than leaving its Block ids published forever.
        rules.clear();
        orch.install_for_sid("S-1-5-21-A").unwrap();
        for id in &armed_ids {
            assert!(
                !registry.contains(*id),
                "a disarmed SID's stale Block ids must not linger in the registry",
            );
        }
    }

    #[test]
    fn mode_b_catch_all_fails_open_without_server_exemption() {
        let (api, orch, src, rules) = fixture_with_resolution(Some(KillSwitchResolution {
            secondary_luid: KS_LUID,
            bootstrap_server_ips: vec![], // unknown server → must not arm
            local_subnets: vec![],
        }));
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
        // Fail-OPEN posture: the catch-all refusing to arm without a server
        // exemption (to avoid a reconnect deadlock) is the fail-open contract.
        // Under fail-closed the user has explicitly opted to cut everything,
        // so it DOES arm — that path is covered by
        // `kill_switch_fail_closed_mode_b_blocks_all_when_unresolved`.
        let mut s = snap_block_mode_b("Wi-Fi", "TAP");
        s.kill_switch_fail_closed = false;
        src.set("S-1-5-21-A", s);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        assert_eq!(
            filters
                .iter()
                .filter(|f| f.action == WfpAction::Block)
                .count(),
            0,
            "fail-open + no server exemption → catch-all must not arm (avoid reconnect deadlock)"
        );
    }

    #[test]
    fn kill_switch_appends_egress_pair_over_secondary_destination() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
        rules.set(rules_with_secondary_ip(ip));
        src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

        let count = orch.install_for_sid("S-1-5-21-A").unwrap();
        // 1 rule permit + ALE pair (permit+block) + packet pair (egress
        // permit + block per named packet protocol — 16.HW-0716) =
        // 1 + 2 + 4×2 = 11 (all protocols by default).
        assert_eq!(count, 11);

        let filters = api.wfp_filters.lock().unwrap();
        assert_eq!(filters.len(), 11);
        // Egress-conditional permits carry the LUID — the ALE one plus one per
        // named packet protocol — all over the protected destination.
        let egress_permits: Vec<_> = filters
            .iter()
            .filter(|f| f.local_interface_luid == Some(KS_LUID))
            .collect();
        assert_eq!(egress_permits.len(), 5);
        assert!(egress_permits
            .iter()
            .all(|f| f.action == WfpAction::Permit && f.remote_ip == Some(ip)));
        // Blocks (1 ALE + 4 named packet), all over the same IP, unconditional
        // on the egress interface.
        let blocks: Vec<_> = filters
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .collect();
        assert_eq!(blocks.len(), 5);
        assert!(blocks
            .iter()
            .all(|f| f.remote_ip == Some(ip) && f.local_interface_luid.is_none()));
    }

    #[test]
    fn reconcile_swaps_stale_luid_permit_and_keeps_blocks() {
        // regression: a secondary adapter reconnect that changes the
        // secondary LUID must install the new-LUID egress permits and reap the
        // dead old-LUID ones, WITHOUT touching the (LUID-free) block filters —
        // window-free (the guard is never lifted).
        use std::sync::atomic::{AtomicU64, Ordering};
        const LUID_A: u64 = 0xAAAA_0000_0000_0001;
        const LUID_B: u64 = 0xBBBB_0000_0000_0002;
        let ip = Ipv4Addr::new(203, 0, 113, 9);

        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let luid_cell = Arc::new(AtomicU64::new(LUID_A));
        let luid_for_resolver = Arc::clone(&luid_cell);
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_kill_switch_resolver(Arc::new(move |_| {
                Some(KillSwitchResolution {
                    secondary_luid: luid_for_resolver.load(Ordering::SeqCst),
                    ..Default::default()
                })
            })),
        );
        rules.set(rules_with_secondary_ip(ip));
        source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

        // Initial install with LUID_A.
        orch.install_for_sid("S-1-5-21-A").unwrap();
        let block_ids_before: std::collections::HashSet<u64> = api
            .wfp_filters
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .map(|f| f.id.raw)
            .collect();
        assert_eq!(
            block_ids_before.len(),
            5,
            "blocks armed: 1 ALE + 4 named packet (16.HW-0716)"
        );
        assert_eq!(
            api.wfp_filters
                .lock()
                .unwrap()
                .iter()
                .filter(|f| f.local_interface_luid == Some(LUID_A))
                .count(),
            5,
            "egress permits pinned to LUID_A: 1 ALE + 4 named packet"
        );

        // Secondary adapter reconnect: the resolver now yields a new LUID.
        luid_cell.store(LUID_B, Ordering::SeqCst);
        let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();
        assert_eq!(
            added, 5,
            "reconcile installs the five new-LUID egress permits"
        );

        let after = api.wfp_filters.lock().unwrap();
        assert_eq!(
            after
                .iter()
                .filter(|f| f.local_interface_luid == Some(LUID_B))
                .count(),
            5,
            "new-LUID egress permits installed"
        );
        assert_eq!(
            after
                .iter()
                .filter(|f| f.local_interface_luid == Some(LUID_A))
                .count(),
            0,
            "dead old-LUID permits reaped (gap #2 fix)"
        );
        let block_ids_after: std::collections::HashSet<u64> = after
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .map(|f| f.id.raw)
            .collect();
        assert_eq!(
            block_ids_after, block_ids_before,
            "block filters unchanged across the swap — window-free, guard never lifted"
        );
    }

    #[test]
    fn reconcile_is_noop_when_luid_and_ips_unchanged() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
        rules.set(rules_with_secondary_ip(ip));
        src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
        orch.install_for_sid("S-1-5-21-A").unwrap();
        let before = api.wfp_filters.lock().unwrap().len();

        let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();
        assert_eq!(added, 0, "stable LUID + IP set → reconcile is a no-op");
        assert_eq!(
            api.wfp_filters.lock().unwrap().len(),
            before,
            "filter set unchanged when nothing changed"
        );
    }

    #[test]
    fn reconcile_is_noop_for_uninstalled_sid() {
        let (_api, orch, _src, _rules) = fixture_with_luid(Some(KS_LUID));
        // No install_for_sid → the SID is unknown; reconcile must not panic or
        // install anything (that path is owned by `reconcile`).
        assert_eq!(orch.reconcile_secondary_coverage("S-1-5-21-Z").unwrap(), 0);
    }

    #[test]
    fn kill_switch_arms_when_secondary_bound_even_without_flag() {
        // binding a secondary adapter is itself the
        // request to protect its traffic, so the leak-guard now arms on the
        // bound secondary alone, even with the opt-in
        // `block_secondary_when_unavailable` toggle OFF. Before 0706 this SID
        // carried only the bare rule permit and leaked to the primary the
        // instant the secondary adapter dropped (HW test #2/#8: zero kill-switch codegen
        // log lines for the whole run because the gate was toggle-only).
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
        rules.set(rules_with_secondary_ip(ip));
        // block_secondary_when_unavailable is false in snap_full — the bound
        // secondary must arm the guard regardless of the opt-in toggle.
        let s = snap_full("Wi-Fi", "TAP");
        assert!(!s.block_secondary_when_unavailable);
        src.set("S-1-5-21-A", s);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        // The LUID-conditional egress pair (permit-via-secondary + block-off-secondary) is
        // the kill-switch's signature — its presence proves the guard armed off
        // the bound secondary alone, with the toggle still off.
        assert!(
            filters
                .iter()
                .any(|f| f.local_interface_luid == Some(KS_LUID)),
            "a bound secondary must arm the LUID-pinned kill-switch even with the toggle off",
        );
        assert!(
            filters.iter().any(|f| f.action == WfpAction::Block),
            "the kill-switch must install the off-secondary block half",
        );
    }

    #[test]
    fn strict_mode_arms_leak_guard_even_without_explicit_flag() {
        // regression for the Strict-mode leak.
        // Choosing StrictSecondaryFailClosed as the default-route mode must
        // install block filters on its own: the Fail-Closed banner probe
        // already reports this mode as "protected", so if enforcement gated
        // only on `block_secondary_when_unavailable` the real IP would leak
        // while the UI claimed protection.
        let (api, orch, src, rules) = fixture_with_resolution(Some(full_ks_resolution()));
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
        let mut s = snap_full("Wi-Fi", "TAP");
        s.mode = PerSidBehaviorMode::StrictSecondaryFailClosed;
        // The separate toggle stays OFF on purpose — the strict MODE alone
        // must arm the guard.
        assert!(!s.block_secondary_when_unavailable);
        src.set("S-1-5-21-A", s);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        // The catch-all kill-switch is the only source of an egress-via-secondary
        // exemption (LUID-conditional permit) and the loopback/link-local/LAN
        // subnet exemptions — their presence proves the guard armed off the
        // strict MODE alone (the toggle was off). Before the fix this SID would
        // carry none of them.
        assert_eq!(
            filters
                .iter()
                .filter(|f| f.local_interface_luid == Some(KS_LUID))
                .count(),
            2,
            "strict mode arms the catch-all: egress-via-secondary exemption at both layers (0704 P2)",
        );
        assert!(
            filters.iter().filter(|f| f.remote_subnet.is_some()).count() >= 3,
            "strict mode arms the catch-all: loopback + link-local + LAN exemptions present",
        );
    }

    #[test]
    fn reconcile_swaps_block_shape_on_vpn_loss_without_uncovering() {
        // the secondary adapter disappears
        // (resolver Some→None) under fail-closed. reconcile swaps the per-dest
        // block SHAPE (block_off_secondary → fail-closed ale_block) make-before-
        // break: the destination stays covered by a block after the swap, and
        // the dead egress permit is reaped.
        use std::sync::atomic::{AtomicBool, Ordering};
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let vpn_up = Arc::new(AtomicBool::new(true));
        let vpn_for_resolver = Arc::clone(&vpn_up);
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_kill_switch_resolver(Arc::new(move |_| {
                if vpn_for_resolver.load(Ordering::SeqCst) {
                    Some(KillSwitchResolution {
                        secondary_luid: KS_LUID,
                        ..Default::default()
                    })
                } else {
                    None // secondary adapter gone
                }
            })),
        );
        rules.set(rules_with_secondary_ip(ip));
        let mut s = snap_block("Wi-Fi", "TAP");
        s.kill_switch_fail_closed = true;
        source.set("S-1-5-21-A", s);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        assert!(
            api.wfp_filters
                .lock()
                .unwrap()
                .iter()
                .any(|f| f.action == WfpAction::Block && f.remote_ip == Some(ip)),
            "dest covered by a block while secondary adapter up"
        );

        // Secondary adapter disappears → fail-closed branch.
        vpn_up.store(false, Ordering::SeqCst);
        orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();
        let after = api.wfp_filters.lock().unwrap();
        assert!(
            after.iter().any(|f| f.action == WfpAction::Block
                && (f.remote_ip == Some(ip) || f.remote_ip.is_none())),
            "dest still covered by a block after secondary adapter loss — no uncovering window"
        );
        assert_eq!(
            after
                .iter()
                .filter(|f| f.local_interface_luid == Some(KS_LUID))
                .count(),
            0,
            "dead-LUID egress permit reaped on the transition"
        );
    }

    #[test]
    fn builtin_vpn_globs_resolve_to_paths_no_glob_in_fail_closed_set() {
        // with the secondary unresolved (VPN down) the
        // `None` fail-closed branch installs the built-in VPN-client exemption
        // permits so the client can bootstrap through the block. Those permits must
        // carry RESOLVED on-disk paths, never the raw `DEFAULT_VPN_EXEMPT_PATTERNS`
        // globs — a glob in `ALE_APP_ID` is silently dropped at apply, so a
        // verbatim glob would trap the client under its own kill-switch.
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        // Map the built-in `openvpn*` glob to a concrete exe; the other built-ins
        // resolve to nothing (client not installed) and simply drop out.
        let resolver = nrr_platform_api::MockAppPathResolver::new().with(
            "openvpn.exe",
            vec![std::path::PathBuf::from(r"C:\Tools\openvpn.exe")],
        );
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_app_resolver(Arc::new(resolver))
            // Secondary unresolved → the `None` fail-closed branch (VPN down).
            .with_kill_switch_resolver(Arc::new(|_| None)),
        );
        rules.set(rules_with_n_primary_ips(1));
        source.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();

        // The resolved openvpn path is present as an exempt Permit (no remote ip).
        assert!(
            filters.iter().any(|f| f.action == WfpAction::Permit
                && f.remote_ip.is_none()
                && f.app_pattern.as_deref() == Some(r"C:\Tools\openvpn.exe")),
            "built-in openvpn glob installed an exempt permit stamped with the resolved path",
        );
        // The core HW-0716 assertion: NO installed filter carries a glob in
        // `app_pattern` — a verbatim glob would never enforce.
        assert!(
            filters.iter().all(|f| f
                .app_pattern
                .as_deref()
                .map(|p| !p.contains('*') && !p.contains('?'))
                .unwrap_or(true)),
            "no glob may leave the orchestrator's fail-closed exempt set",
        );
    }

    #[test]
    fn reconcile_reaps_dead_permits_even_when_new_permit_add_skips() {
        // a SKIPPED PERMIT must NOT defer the delete:
        // skipping a permit only tightens (the block half stays), so the dead-LUID
        // permits are still reaped. This keeps gap #2 working on reconnects even
        // when a secondary rule's app is unresolvable — the over-broad "any skip
        // defers" gate would have re-defeated the fix here.
        use std::sync::atomic::{AtomicU64, Ordering};
        const LUID_A: u64 = 0xAAAA_0000_0000_0001;
        const LUID_B: u64 = 0xBBBB_0000_0000_0002;
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let luid_cell = Arc::new(AtomicU64::new(LUID_A));
        let luid_for_resolver = Arc::clone(&luid_cell);
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_kill_switch_resolver(Arc::new(move |_| {
                Some(KillSwitchResolution {
                    secondary_luid: luid_for_resolver.load(Ordering::SeqCst),
                    ..Default::default()
                })
            })),
        );
        rules.set(rules_with_secondary_ip(ip));
        source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
        orch.install_for_sid("S-1-5-21-A").unwrap();

        // Force every LUID_B egress PERMIT's ADD to skip (blocks add fine).
        let luid_b_permit_ids: Vec<u64> = crate::killswitch_codegen::kill_switch_filters(
            "S-1-5-21-A",
            &[ip],
            LUID_B,
            crate::killswitch_codegen::KillSwitchProtocols::from_bits(0x7F),
        )
        .iter()
        .filter(|s| s.action == WfpAction::Permit)
        .map(|s| s.id.raw)
        .collect();
        assert!(!luid_b_permit_ids.is_empty());
        api.set_fail_add_unmaterializable(&luid_b_permit_ids);

        // Reconnect: LUID flips to B; the new permits skip but no BLOCK skipped.
        luid_cell.store(LUID_B, Ordering::SeqCst);
        orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

        let after = api.wfp_filters.lock().unwrap();
        // The dead LUID_A permits WERE reaped (permit skip does not defer).
        assert_eq!(
            after
                .iter()
                .filter(|f| f.local_interface_luid == Some(LUID_A))
                .count(),
            0,
            "gap #2 preserved: dead-LUID permits reaped despite a skipped replacement permit"
        );
        // The block still covers the dest (fail-safe — no leak while the new
        // permit is absent).
        assert!(
            after
                .iter()
                .any(|f| f.action == WfpAction::Block && f.remote_ip == Some(ip)),
            "dest stays covered by its block"
        );
    }

    #[test]
    fn reconcile_defers_delete_when_replacement_block_add_skipped() {
        // (gap #2 leak-safety — the DEFECT the adversarial verify
        // found): if a replacement BLOCK's ADD is best-effort-SKIPPED, the
        // superseded block must NOT be deleted (else its dest is uncovered → leak).
        // Here the rule's dest changes IP1→IP2 on a reconnect and IP2's new block
        // is forced to skip, so IP1's OLD block must survive (delete deferred).
        use std::sync::atomic::{AtomicU64, Ordering};
        const LUID_A: u64 = 0xAAAA_0000_0000_0001;
        const LUID_B: u64 = 0xBBBB_0000_0000_0002;
        let ip1 = Ipv4Addr::new(203, 0, 113, 9);
        let ip2 = Ipv4Addr::new(198, 51, 100, 7);
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let luid_cell = Arc::new(AtomicU64::new(LUID_A));
        let luid_for_resolver = Arc::clone(&luid_cell);
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_kill_switch_resolver(Arc::new(move |_| {
                Some(KillSwitchResolution {
                    secondary_luid: luid_for_resolver.load(Ordering::SeqCst),
                    ..Default::default()
                })
            })),
        );
        rules.set(rules_with_secondary_ip(ip1));
        source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
        orch.install_for_sid("S-1-5-21-A").unwrap();

        // Force IP2's new BLOCK adds to be unmaterializable (its permits add fine).
        let ip2_block_ids: Vec<u64> = crate::killswitch_codegen::kill_switch_filters(
            "S-1-5-21-A",
            &[ip2],
            LUID_B,
            crate::killswitch_codegen::KillSwitchProtocols::from_bits(0x7F),
        )
        .iter()
        .filter(|s| s.action == WfpAction::Block)
        .map(|s| s.id.raw)
        .collect();
        assert!(!ip2_block_ids.is_empty());
        api.set_fail_add_unmaterializable(&ip2_block_ids);

        // Rule dest changes IP1→IP2 and the secondary adapter reconnects to LUID_B.
        rules.set(rules_with_secondary_ip(ip2));
        luid_cell.store(LUID_B, Ordering::SeqCst);
        orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

        // IP2's block add skipped → the whole delete pass is deferred, so IP1's
        // OLD block survives (over-coverage) rather than being torn down while a
        // replacement block is missing.
        assert!(
            api.wfp_filters
                .lock()
                .unwrap()
                .iter()
                .any(|f| f.action == WfpAction::Block && f.remote_ip == Some(ip1)),
            "delete deferred: old block survives when a replacement block add was skipped"
        );
    }

    #[test]
    fn is_app_only_block_classifies_only_appscoped_dest_less_blocks() {
        // the deferral gate must arm on destination-covering block
        // skips (leak risk) but NOT on app-only block skips (a missing exe
        // covers no destination and otherwise deferred the delete pass forever).
        use nrr_platform_api::types::WfpLayerKey;
        fn spec(
            action: WfpAction,
            remote_ip: Option<Ipv4Addr>,
            app: Option<&str>,
            subnet: Option<(Ipv4Addr, u8)>,
        ) -> WfpFilterSpec {
            WfpFilterSpec {
                layer: WfpLayerKey::AleAuthConnectV4,
                action,
                remote_ip,
                remote_port: None,
                weight: 0,
                id: WfpFilterId::from_raw(1),
                user_sid: None,
                app_pattern: app.map(str::to_string),
                local_interface_luid: None,
                remote_subnet: subnet,
                remote_subnet_v6: None,
                ip_protocol: None,
            }
        }
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        // App-scoped block with no destination → app-only (gate must NOT arm).
        assert!(is_app_only_block(&spec(
            WfpAction::Block,
            None,
            Some("C:/app.exe"),
            None
        )));
        // App-scoped block that ALSO pins a destination IP → not app-only.
        assert!(!is_app_only_block(&spec(
            WfpAction::Block,
            Some(ip),
            Some("C:/app.exe"),
            None
        )));
        // Catch-all block (no remote, no app) → not app-only (must arm the gate).
        assert!(!is_app_only_block(&spec(
            WfpAction::Block,
            None,
            None,
            None
        )));
        // Destination block (remote_ip, no app) → not app-only.
        assert!(!is_app_only_block(&spec(
            WfpAction::Block,
            Some(ip),
            None,
            None
        )));
        // Subnet block → not app-only.
        assert!(!is_app_only_block(&spec(
            WfpAction::Block,
            None,
            None,
            Some((ip, 24))
        )));
        // A PERMIT is never a "block", regardless of app scope.
        assert!(!is_app_only_block(&spec(
            WfpAction::Permit,
            None,
            Some("C:/app.exe"),
            None
        )));
    }

    #[test]
    fn kill_switch_fails_open_when_luid_unresolved_and_posture_is_fail_open() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        // Flag is ON but posture is fail-OPEN, and the LUID can't resolve.
        let (api, orch, src, rules) = fixture_with_luid(None);
        rules.set(rules_with_secondary_ip(ip));
        src.set("S-1-5-21-A", snap_block_fail_open("Wi-Fi", "TAP"));

        let count = orch.install_for_sid("S-1-5-21-A").unwrap();
        assert_eq!(count, 1, "fail-open → no kill-switch, no black hole");
        let filters = api.wfp_filters.lock().unwrap();
        assert!(
            filters
                .iter()
                .all(|f| f.action == WfpAction::Permit && f.local_interface_luid.is_none()),
            "fail-open leaves only the rule permit — no block, no egress condition"
        );
    }

    #[test]
    fn kill_switch_fail_closed_blocks_secondary_dest_when_luid_unresolved() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        // Flag ON, posture fail-CLOSED (the default), LUID unresolvable
        // (secondary adapter gone / never bound) → the protected destination must be
        // BLOCKED, not leaked. This is HW-test finding #4.
        let (api, orch, src, rules) = fixture_with_luid(None);
        rules.set(rules_with_secondary_ip(ip));
        src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

        let count = orch.install_for_sid("S-1-5-21-A").unwrap();
        // rule permit (1) + fail-closed blocks over the dest: 1 ALE (TCP/UDP)
        // + 4 named packet blocks (16.HW-0716: ICMP/IGMP/GRE/ESP) = 5 blocks.
        assert_eq!(count, 6 + EXEMPT);
        let filters = api.wfp_filters.lock().unwrap();
        let blocks: Vec<_> = filters
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .collect();
        assert_eq!(
            blocks.len(),
            5,
            "fail-closed blocks the secondary dest at the ALE + named packet layers"
        );
        for b in &blocks {
            assert_eq!(b.remote_ip, Some(ip));
            assert_eq!(
                b.local_interface_luid, None,
                "no tunnel to permit through — the block is unconditional"
            );
        }
    }

    #[test]
    fn link_provider_app_earns_app_exempt_permit_under_fail_closed() {
        // the user-confirmed link-provider app (VPN client)
        // must be permitted through the fail-closed kill-switch by app id, so
        // the app that establishes the secondary link can always (re)connect
        // (the C4 self-blocking class from HW-0717/0718: the client could not
        // reach its server until the kill-switch was disabled).
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let (api, orch, src, rules) = fixture_with_luid(None); // secondary unresolved
        rules.set(rules_with_secondary_ip(ip));
        let mut snap = snap_block("Wi-Fi", "TAP");
        snap.link_provider_exe_paths = vec!["C:\\Apps\\tunnel-client.exe".into()];
        src.set("S-1-5-21-A", snap);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        let exempt = filters
            .iter()
            .find(|f| {
                f.action == WfpAction::Permit
                    && f.app_pattern.as_deref() == Some("C:\\Apps\\tunnel-client.exe")
            })
            .expect("configured link-provider app must earn an ALE app-id permit");
        assert!(
            exempt.weight >= 0x0060_0000,
            "the provider permit must sit in the APP_EXEMPT band above every kill-switch block (got {:#x})",
            exempt.weight
        );
        assert_eq!(
            exempt.user_sid.as_deref(),
            Some("S-1-5-21-A"),
            "ALE app exemption stays scoped to the caller SID"
        );
    }

    // ── Proactive VPN-client app exemption ─────────────────────

    /// [`fixture_with_resolution`] plus a wired verified-VPN-client provider,
    /// for the proactive app-exemption tests.
    #[allow(clippy::type_complexity)]
    fn fixture_with_resolution_and_vpn_clients(
        resolution: Option<KillSwitchResolution>,
        client_paths: Vec<String>,
    ) -> (
        Arc<MockWindowsApi>,
        Arc<PerSidApplyOrchestrator>,
        Arc<ScriptedSource>,
        Arc<ScriptedRules>,
    ) {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
            .with_vpn_client_apps_provider(Arc::new(move || client_paths.clone())),
        );
        (api, orch, source, rules)
    }

    const VPN_CLIENT_PATH: &str = r"C:\Apps\hidemy.name vpn 3.0.exe";

    /// Find the app-exempt permit for [`VPN_CLIENT_PATH`], if any installed.
    fn find_client_exempt(
        filters: &[nrr_platform_api::WfpFilterRecord],
    ) -> Option<nrr_platform_api::WfpFilterRecord> {
        filters
            .iter()
            .find(|f| {
                f.action == WfpAction::Permit
                    && f.app_pattern.as_deref() == Some(VPN_CLIENT_PATH)
                    && f.local_interface_luid.is_none()
            })
            .cloned()
    }

    #[test]
    fn verified_vpn_client_exempt_installed_when_mode_b_catch_all_arms() {
        // The core proactive guarantee: the catch-all arms with the tunnel UP,
        // and the verified client's app permit is installed IN THE SAME
        // compute — before any drop of the session. Its connectivity checks
        // against rotating provider IPs over the primary link then always
        // escape by app id, so the reactive per-IP learner is no longer on the
        // critical path.
        let (api, orch, src, rules) = fixture_with_resolution_and_vpn_clients(
            Some(full_ks_resolution()),
            vec![VPN_CLIENT_PATH.to_string()],
        );
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
        src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        let exempt = find_client_exempt(&filters)
            .expect("verified VPN client must earn an app permit when the catch-all arms");
        assert!(
            exempt.weight >= 0x0060_0000,
            "client permit must sit in the APP_EXEMPT band above the catch-all block (got {:#x})",
            exempt.weight
        );
        assert_eq!(
            exempt.user_sid.as_deref(),
            Some("S-1-5-21-A"),
            "app exemption stays scoped to the caller SID"
        );
        assert_eq!(
            exempt.remote_ip, None,
            "app-scoped, not destination-scoped — IP rotation must not matter"
        );
    }

    #[test]
    fn verified_vpn_client_exempt_installed_when_pair_cannot_arm_fail_closed() {
        // Resolution exists (LUID known) but carries no bootstrap server IPs,
        // so the mode-B catch-all cannot arm and the posture falls back to
        // fail-closed blocking — the client app must be permitted through that
        // block too (this branch historically emitted no app exemptions).
        let resolution = KillSwitchResolution {
            secondary_luid: KS_LUID,
            bootstrap_server_ips: Vec::new(),
            local_subnets: Vec::new(),
        };
        let (api, orch, src, rules) = fixture_with_resolution_and_vpn_clients(
            Some(resolution),
            vec![VPN_CLIENT_PATH.to_string()],
        );
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
        src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        let exempt = find_client_exempt(&filters)
            .expect("verified VPN client must be permitted through the fail-closed block");
        assert!(exempt.weight >= 0x0060_0000);
    }

    #[test]
    fn verified_vpn_client_exempt_not_emitted_for_mode_a_pinning() {
        // Mode A with the tunnel UP arms only per-destination pins — there is
        // no catch-all, so an unconditional app permit would only weaken the
        // pinned-destination guarantee. The proactive exemption must stay out.
        let (api, orch, src, rules) = fixture_with_resolution_and_vpn_clients(
            Some(full_ks_resolution()),
            vec![VPN_CLIENT_PATH.to_string()],
        );
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
        src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP")); // PreferPrimary

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        assert!(
            find_client_exempt(&filters).is_none(),
            "mode A per-destination pinning must not carry an app-wide permit"
        );
    }

    #[test]
    fn fail_closed_block_all_permits_known_primary_ip_but_not_shared_secondary() {
        // under a Mode-A FailClosedUnknown
        // block-all (secondary unresolved), a host matched ONLY by a primary
        // rule earns a packet-layer permit (ping survives), but a host matched
        // by BOTH primary and secondary rules stays blocked (it is
        // secondary-destined; while the secondary is down it must fail closed).
        use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
        let primary_only = Ipv4Addr::new(203, 0, 113, 20);
        let shared = Ipv4Addr::new(203, 0, 113, 21);
        let (api, orch, src, rules) = fixture_with_luid(None); // secondary unresolved
        rules.set(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![
                    primary_ip_rule("r-pri", primary_only),
                    primary_ip_rule("r-shared-pri", shared),
                ]),
                secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                    id: RuleId("r-shared-sec".into()),
                    enabled: true,
                    address_match: Some(CanonicalAddressMatch::ExactIp(shared)),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_domain::RuleAction::Route,
                    origin: None,
                }]),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        });
        let mut snap = snap_block("Wi-Fi", "TAP");
        snap.mode_a_coverage_strategy = ModeACoverageStrategy::FailClosedUnknown;
        src.set("S-1-5-21-A", snap);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        use nrr_platform_api::types::WfpLayerKey;
        let has_primary_permit = |ip: Ipv4Addr| {
            filters.iter().any(|f| {
                f.layer == WfpLayerKey::OutboundTransportV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(ip)
                    && f.ip_protocol.is_none()
            })
        };
        assert!(
            has_primary_permit(primary_only),
            "a primary-only host gets a transport permit so ping survives the block-all (HW-0718)"
        );
        assert!(
            !has_primary_permit(shared),
            "a shared primary+secondary IP stays blocked while the secondary is down"
        );
    }

    /// [`FqdnCacheLookup`] wrapper with a scripted shared-IP census — for the
    /// smart-kill-switch exemption tests.
    struct CensusCache {
        inner: MockFqdnCacheLookup,
        shared: std::collections::HashSet<Ipv4Addr>,
    }
    impl FqdnCacheLookup for CensusCache {
        fn ips_for_hostname(&self, hostname: &str) -> Vec<Ipv4Addr> {
            self.inner.ips_for_hostname(hostname)
        }
        fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
            self.inner.hostnames_under_suffix(suffix, limit)
        }
        fn direct_host_count_for_ip(&self, ip: Ipv4Addr) -> u32 {
            u32::from(self.shared.contains(&ip))
        }
        fn shared_direct_ips(&self) -> std::collections::HashSet<Ipv4Addr> {
            self.shared.clone()
        }
    }

    /// Like [`fixture_with_resolution`], but with a scripted shared-IP census
    /// and an optional known-direct registry. `fake_ip_effective` scripts the
    /// live "hostname enforcement is active" signal the smart shared-IP
    /// exemption gates on: while `true` the fake-IP context
    /// provider yields an enabled scope, mirroring the production provider's
    /// toggle-AND-Resolver-AND-running condition; flip it between installs to
    /// model a datapath transition.
    #[allow(clippy::type_complexity)]
    fn fixture_with_census(
        resolution: Option<KillSwitchResolution>,
        shared: &[Ipv4Addr],
        known_direct: Option<Arc<crate::known_direct::KnownDirectRegistry>>,
        fake_ip_effective: Arc<std::sync::atomic::AtomicBool>,
    ) -> (
        Arc<MockWindowsApi>,
        Arc<PerSidApplyOrchestrator>,
        Arc<ScriptedSource>,
        Arc<ScriptedRules>,
    ) {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(CensusCache {
            inner: MockFqdnCacheLookup::new(),
            shared: shared.iter().copied().collect(),
        });
        let audit = Arc::new(CollectAudit::default());
        let mut orch = PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
        .with_fake_ip_context_provider(Arc::new(move || {
            fake_ip_effective
                .load(std::sync::atomic::Ordering::Relaxed)
                .then(|| crate::fake_ip::FakeIpEnforcementContext {
                    scope: nrr_platform_api::fake_ip::FakeIpScope::enabled(Vec::<String>::new()),
                    pool: nrr_platform_api::fake_ip::FakeIpPoolConfig::default(),
                })
        }));
        if let Some(reg) = known_direct {
            orch = orch.with_known_direct_registry(reg);
        }
        (api, Arc::new(orch), source, rules)
    }

    #[test]
    fn smart_block_all_spares_census_shared_ip_but_strict_still_blocks_it() {
        //  — under a Mode-A FailClosedUnknown block-all (secondary
        // unresolved = unusable) an IP the census saw on a direct host is NOT
        // pinned by the smart kill-switch, so it must not be subtracted from
        // the known-primary exemption either: the primary/direct co-tenant
        // stays reachable on the primary link instead of being blocked to
        // death against a link that carries nothing. Strict mode keeps the
        // historic pin-everything subtraction.
        //  — the smart leg additionally requires the fake-IP
        // datapath to be effective (hostname enforcement covers the rule
        // host); see `smart_exemption_requires_fake_ip_datapath` for the gate.
        use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
        use std::sync::atomic::AtomicBool;
        let shared = Ipv4Addr::new(209, 85, 233, 84);
        for (strict, expect_permit) in [(false, true), (true, false)] {
            let (api, orch, src, rules) = fixture_with_census(
                None,
                &[shared],
                None,
                Arc::new(AtomicBool::new(true)), // fake-IP effective
            );
            rules.set(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(vec![primary_ip_rule("r-pri", shared)]),
                    secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                        id: RuleId("r-sec".into()),
                        enabled: true,
                        address_match: Some(CanonicalAddressMatch::ExactIp(shared)),
                        app_match: None,
                        comment: String::new(),
                        action: nrr_domain::RuleAction::Route,
                        origin: None,
                    }]),
                },
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            });
            let mut snap = snap_block("Wi-Fi", "TAP");
            snap.mode_a_coverage_strategy = ModeACoverageStrategy::FailClosedUnknown;
            snap.kill_switch_strict_shared_ips = strict;
            src.set("S-1-5-21-A", snap);

            orch.install_for_sid("S-1-5-21-A").unwrap();
            let filters = api.wfp_filters.lock().unwrap();
            use nrr_platform_api::types::WfpLayerKey;
            let has_permit = filters.iter().any(|f| {
                f.layer == WfpLayerKey::OutboundTransportV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(shared)
                    && f.ip_protocol.is_none()
            });
            assert_eq!(
                has_permit, expect_permit,
                "strict={strict}: census-shared IP exemption under the block-all"
            );
        }
    }

    #[test]
    fn known_direct_exemption_keeps_census_shared_ip_under_mode_b_block_all() {
        //  — the known-direct subtraction removes only PINNED IPs. A
        // census-shared IP (pin skipped while the secondary is unusable) stays
        // exemptible, so a direct co-tenant registered by a Mode-B answer
        // survives the block-all; a pinned (non-shared) secondary destination
        // is still subtracted and stays blocked. Requires an effective fake-IP
        // datapath since  (the rule host is then enforced by name).
        use std::sync::atomic::AtomicBool;
        let shared = Ipv4Addr::new(209, 85, 233, 84);
        let pinned = Ipv4Addr::new(203, 0, 113, 9);
        let registry = Arc::new(crate::known_direct::KnownDirectRegistry::default());
        registry.register(&[shared, pinned]);
        let (api, orch, src, rules) = fixture_with_census(
            None,
            &[shared],
            Some(Arc::clone(&registry)),
            Arc::new(AtomicBool::new(true)), // fake-IP effective
        );
        rules.set(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::default(),
                secondary: CanonicalRuleSet::from_rules(vec![
                    primary_ip_rule("r-sec-1", shared),
                    primary_ip_rule("r-sec-2", pinned),
                ]),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        });
        let mut snap = snap_block_mode_b("Wi-Fi", "TAP");
        snap.kill_switch_strict_shared_ips = false;
        src.set("S-1-5-21-A", snap);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        use nrr_platform_api::types::WfpLayerKey;
        // Only filters in the catch-all EXEMPT band (0x0050_0000+) count —
        // the rule's own ALE permit sits in a lower band and exists for both
        // IPs regardless of the known-direct exemption.
        let exempt_permit = |ip: Ipv4Addr| {
            filters.iter().any(|f| {
                f.layer == WfpLayerKey::AleAuthConnectV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(ip)
                    && f.weight >= 0x0050_0000
            })
        };
        assert!(
            exempt_permit(shared),
            "census-shared known-direct IP earns its block-all exemption (pin skipped)"
        );
        assert!(
            !exempt_permit(pinned),
            "a pinned secondary destination is still subtracted from the exemption"
        );
    }

    /// The rule book shared by the fake-IP-gate tests below: one census-shared
    /// IP matched by BOTH a primary and a secondary rule.
    fn shared_ip_rule_book(shared: Ipv4Addr) -> ActiveRulesSnapshot {
        ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![primary_ip_rule("r-pri", shared)]),
                secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                    id: RuleId("r-sec".into()),
                    enabled: true,
                    address_match: Some(CanonicalAddressMatch::ExactIp(shared)),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_domain::RuleAction::Route,
                    origin: None,
                }]),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        }
    }

    #[test]
    fn smart_exemption_requires_fake_ip_datapath() {
        //  — with the fake-IP datapath NOT effective the IP pin/block
        // set is the ONLY enforcement, so the smart shared-IP relaxation must
        // fall back to the strict subtraction: a census-shared secondary
        // destination earns NO known-primary permit under the block-all (in
        // the  run, 39 chatgpt.com connections egressed the primary
        // through this exemption while the rule host was fail-closed).
        use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
        use std::sync::atomic::AtomicBool;
        let shared = Ipv4Addr::new(209, 85, 233, 84);
        let (api, orch, src, rules) = fixture_with_census(
            None,
            &[shared],
            None,
            Arc::new(AtomicBool::new(false)), // fake-IP NOT effective
        );
        rules.set(shared_ip_rule_book(shared));
        let mut snap = snap_block("Wi-Fi", "TAP");
        snap.mode_a_coverage_strategy = ModeACoverageStrategy::FailClosedUnknown;
        snap.kill_switch_strict_shared_ips = false; // smart mode requested
        src.set("S-1-5-21-A", snap);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        use nrr_platform_api::types::WfpLayerKey;
        assert!(
            !filters.iter().any(|f| {
                f.layer == WfpLayerKey::OutboundTransportV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(shared)
                    && f.ip_protocol.is_none()
            }),
            "without an effective fake-IP datapath a census-shared secondary \
             destination must stay blocked under the block-all (strict subtraction)"
        );
    }

    #[test]
    fn known_direct_exemption_denied_for_shared_ip_when_fake_ip_not_effective() {
        //  — the known-direct rescue path (the proven
        // egress route) must apply the same fake-IP gate: with the datapath
        // down, a census-shared known-direct IP is subtracted like any other
        // secondary destination and earns no block-all exemption.
        use std::sync::atomic::AtomicBool;
        let shared = Ipv4Addr::new(209, 85, 233, 84);
        let registry = Arc::new(crate::known_direct::KnownDirectRegistry::default());
        registry.register(&[shared]);
        let (api, orch, src, rules) = fixture_with_census(
            None,
            &[shared],
            Some(Arc::clone(&registry)),
            Arc::new(AtomicBool::new(false)), // fake-IP NOT effective
        );
        rules.set(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::default(),
                secondary: CanonicalRuleSet::from_rules(vec![primary_ip_rule("r-sec", shared)]),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        });
        let mut snap = snap_block_mode_b("Wi-Fi", "TAP");
        snap.kill_switch_strict_shared_ips = false;
        src.set("S-1-5-21-A", snap);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        use nrr_platform_api::types::WfpLayerKey;
        assert!(
            !filters.iter().any(|f| {
                f.layer == WfpLayerKey::AleAuthConnectV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(shared)
                    && f.weight >= 0x0050_0000
            }),
            "known-direct must not rescue a census-shared secondary destination \
             while fake-IP is not covering the rule host by name"
        );
    }

    #[test]
    fn fake_ip_datapath_flip_retightens_shared_ip_exemption_on_recompute() {
        //  — the gate is read LIVE on every compute, so the replan
        // fired on a fake-IP toggle/datapath transition (the composition
        // root's fake-IP replan hook, which runs the window-free
        // `recompile_for_sid` diff) is sufficient to tighten or loosen the
        // exemption: same SID, same rules, only the datapath signal flips
        // between passes. The tightening pass must also DELETE the superseded
        // permit — an add-only pass would leave the leak installed.
        use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
        use std::sync::atomic::{AtomicBool, Ordering};
        let shared = Ipv4Addr::new(209, 85, 233, 84);
        let effective = Arc::new(AtomicBool::new(true));
        let (api, orch, src, rules) =
            fixture_with_census(None, &[shared], None, Arc::clone(&effective));
        rules.set(shared_ip_rule_book(shared));
        let mut snap = snap_block("Wi-Fi", "TAP");
        snap.mode_a_coverage_strategy = ModeACoverageStrategy::FailClosedUnknown;
        snap.kill_switch_strict_shared_ips = false;
        src.set("S-1-5-21-A", snap);

        use nrr_platform_api::types::WfpLayerKey;
        let shared_permitted = |api: &MockWindowsApi| {
            api.wfp_filters.lock().unwrap().iter().any(|f| {
                f.layer == WfpLayerKey::OutboundTransportV4
                    && f.action == WfpAction::Permit
                    && f.remote_ip == Some(shared)
                    && f.ip_protocol.is_none()
            })
        };

        orch.install_for_sid("S-1-5-21-A").unwrap();
        assert!(
            shared_permitted(&api),
            "datapath effective: the smart exemption spares the shared IP"
        );

        effective.store(false, Ordering::Relaxed); // datapath died / toggle off
        orch.recompile_for_sid("S-1-5-21-A").unwrap();
        assert!(
            !shared_permitted(&api),
            "recompute after the datapath flip must retighten to the strict subtraction"
        );

        effective.store(true, Ordering::Relaxed); // datapath recovered
        orch.recompile_for_sid("S-1-5-21-A").unwrap();
        assert!(
            shared_permitted(&api),
            "recovery replan restores the smart exemption"
        );
    }

    #[test]
    fn kill_switch_disabled_disarms_leak_guard_even_when_secondary_unresolved() {
        // the MASTER kill-switch toggle is OFF (full opt-in).
        // Even with a secondary bound, the fail-CLOSED posture, and the secondary
        // adapter unresolvable (LUID None) — the exact conditions that block in
        // `kill_switch_fail_closed_blocks_secondary_dest_when_luid_unresolved` —
        // NO fail-closed block may be installed. Any leak is then the user's
        // deliberate choice; only the rule's own permit survives.
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let (api, orch, src, rules) = fixture_with_luid(None);
        rules.set(rules_with_secondary_ip(ip));
        let mut snap = snap_block("Wi-Fi", "TAP");
        snap.kill_switch_enabled = false; // master OFF
        src.set("S-1-5-21-A", snap);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        assert!(
            filters.iter().all(|f| f.action != WfpAction::Block),
            "kill-switch OFF must install ZERO block filters even with the secondary \
             unresolved (full opt-in — leak-guard fully disarmed)"
        );
    }

    #[test]
    fn kill_switch_fail_closed_mode_b_blocks_all_when_unresolved() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        // Mode B (everything-via-secondary), fail-closed, secondary gone →
        // a catch-all block (plus the safe exemptions) must be installed.
        let (api, orch, src, rules) = fixture_with_luid(None);
        rules.set(rules_with_secondary_ip(ip));
        src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        let blocks: Vec<_> = filters
            .iter()
            .filter(|f| {
                f.action == WfpAction::Block && f.remote_ip.is_none() && f.remote_subnet.is_none()
            })
            .collect();
        assert_eq!(
            blocks.len(),
            7,
            "mode-B fail-closed: V4 ALE block-all + 4 named V4 packet blocks              (16.HW-0716) + V6 ALE + V6 packet block-all"
        );
    }

    #[test]
    fn block_all_arming_edge_flushes_os_dns_cache_once_per_transition() {
        // the OS resolver-cache flush fires exactly
        // once on the disarmed→armed edge and once on armed→disarmed; the
        // steady-state reconcile (same compute, every few seconds on HW) must
        // never flush, or the OS cache would be permanently defeated.
        use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let flusher = Arc::new(nrr_platform_api::MockDnsCacheControl::new());
        let orch = PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(|_| None)) // secondary unresolved
        .with_dns_cache_control(
            Arc::clone(&flusher) as Arc<dyn nrr_platform_api::DnsCacheControlPort>
        );
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9)));
        let armed_snap = || {
            let mut s = snap_block("Wi-Fi", "TAP");
            s.mode_a_coverage_strategy = ModeACoverageStrategy::FailClosedUnknown;
            s
        };
        source.set("S-1-5-21-A", armed_snap());

        orch.install_for_sid("S-1-5-21-A").unwrap();
        assert_eq!(flusher.flush_count(), 1, "arming edge must flush once");
        orch.install_for_sid("S-1-5-21-A").unwrap();
        assert_eq!(
            flusher.flush_count(),
            1,
            "steady-state re-apply (reconcile tick) must NOT flush"
        );

        let mut disarmed = armed_snap();
        disarmed.kill_switch_enabled = false; // master OFF → block-all gone
        source.set("S-1-5-21-A", disarmed);
        orch.install_for_sid("S-1-5-21-A").unwrap();
        assert_eq!(flusher.flush_count(), 2, "disarming edge must flush once");
        orch.install_for_sid("S-1-5-21-A").unwrap();
        assert_eq!(
            flusher.flush_count(),
            2,
            "disarmed steady state must NOT flush"
        );
    }

    #[test]
    fn posture_change_latch_reports_transitions_only() {
        // the kill-switch posture log throttle: full-
        // level lines fire only on a posture CHANGE per SID; the ~5 s reconcile
        // re-deriving the same posture must not re-log (NDJSON flood).
        let (_api, orch, _src, _rules) = fixture_with_luid(None);
        assert!(orch.posture_changed("S-A", "active"), "first sighting logs");
        assert!(
            !orch.posture_changed("S-A", "active"),
            "steady state is quiet"
        );
        assert!(
            orch.posture_changed("S-A", "unresolved-fail-closed-block-all"),
            "a posture flip re-logs"
        );
        assert!(
            orch.posture_changed("S-B", "active"),
            "per-SID latches are independent"
        );
        assert!(!orch.posture_changed("S-A", "unresolved-fail-closed-block-all"));
    }

    #[test]
    fn evaluate_posture_log_transitions_on_first_sighting_and_on_change() {
        let t0 = Instant::now();
        // Nothing latched yet → transition.
        let (event, latch) =
            evaluate_posture_log(None, "block-all", t0, POSTURE_HEARTBEAT_INTERVAL);
        assert_eq!(event, PostureLogEvent::Transition);
        assert_eq!(latch.posture, "block-all");

        // Same posture, no time elapsed → steady.
        let (event, latch) =
            evaluate_posture_log(Some(latch), "block-all", t0, POSTURE_HEARTBEAT_INTERVAL);
        assert_eq!(event, PostureLogEvent::Steady);

        // Posture flips (entering a different state) → transition again,
        // even though the interval has not elapsed — a state change is
        // always worth a line, symmetric for entering and leaving.
        let (event, latch) = evaluate_posture_log(
            Some(latch),
            "active",
            t0 + Duration::from_secs(1),
            POSTURE_HEARTBEAT_INTERVAL,
        );
        assert_eq!(event, PostureLogEvent::Transition);
        assert_eq!(latch.posture, "active");
    }

    #[test]
    fn evaluate_posture_log_heartbeats_while_posture_persists() {
        let t0 = Instant::now();
        let (_event, latch) =
            evaluate_posture_log(None, "block-all", t0, POSTURE_HEARTBEAT_INTERVAL);

        // Well before the interval elapses: steady, no line.
        let just_under = t0 + POSTURE_HEARTBEAT_INTERVAL - Duration::from_secs(1);
        let (event, latch) = evaluate_posture_log(
            Some(latch),
            "block-all",
            just_under,
            POSTURE_HEARTBEAT_INTERVAL,
        );
        assert_eq!(event, PostureLogEvent::Steady);

        // Interval elapsed since the posture was entered: heartbeat, with
        // elapsed time measured from entry, not from the last steady check.
        let due = t0 + POSTURE_HEARTBEAT_INTERVAL;
        let (event, latch) =
            evaluate_posture_log(Some(latch), "block-all", due, POSTURE_HEARTBEAT_INTERVAL);
        match event {
            PostureLogEvent::Heartbeat { elapsed } => {
                assert_eq!(elapsed, POSTURE_HEARTBEAT_INTERVAL)
            }
            other => panic!("expected heartbeat, got {other:?}"),
        }

        // Right after a heartbeat fires, the interval resets from that
        // heartbeat (not from the original entry) — no immediate re-fire.
        let (event, _latch) = evaluate_posture_log(
            Some(latch),
            "block-all",
            due + Duration::from_secs(1),
            POSTURE_HEARTBEAT_INTERVAL,
        );
        assert_eq!(event, PostureLogEvent::Steady);
    }

    #[test]
    fn posture_log_event_heartbeats_via_orchestrator_latch() {
        // End-to-end through the orchestrator's own posture_log_event: a
        // long block-all session (the same posture recomputed every ~5 s by
        // the leak-guard reconcile) must not go completely silent between
        // its opening line and whenever it eventually clears.
        let (_api, orch, _src, _rules) = fixture_with_luid(None);
        assert_eq!(
            orch.posture_log_event("S-A", "unresolved-fail-closed-block-all"),
            PostureLogEvent::Transition,
            "entering block-all logs immediately"
        );
        assert_eq!(
            orch.posture_log_event("S-A", "unresolved-fail-closed-block-all"),
            PostureLogEvent::Steady,
            "the very next re-derivation is quiet"
        );
        assert_eq!(
            orch.posture_log_event("S-A", "active"),
            PostureLogEvent::Transition,
            "leaving block-all (posture flip) logs immediately, symmetric with entering"
        );
    }

    #[test]
    fn kill_switch_protects_only_secondary_not_primary_destinations() {
        let primary_ip = Ipv4Addr::new(10, 0, 0, 1);
        let secondary_ip = Ipv4Addr::new(203, 0, 113, 9);
        let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
        rules.set(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                    id: RuleId("r-pri".into()),
                    enabled: true,
                    address_match: Some(CanonicalAddressMatch::ExactIp(primary_ip)),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_domain::RuleAction::Route,
                    origin: None,
                }]),
                secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                    id: RuleId("r-sec".into()),
                    enabled: true,
                    address_match: Some(CanonicalAddressMatch::ExactIp(secondary_ip)),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_domain::RuleAction::Route,
                    origin: None,
                }]),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        });
        src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

        let count = orch.install_for_sid("S-1-5-21-A").unwrap();
        // 2 rule permits (primary + secondary) + kill-switch ALE pair + one
        // packet pair per named protocol (16.HW-0716) = 2 + 2 + 8 = 12.
        assert_eq!(count, 12);
        let filters = api.wfp_filters.lock().unwrap();
        // The kill-switch never targets the primary destination.
        assert!(
            filters
                .iter()
                .filter(|f| f.local_interface_luid == Some(KS_LUID) || f.action == WfpAction::Block)
                .all(|f| f.remote_ip == Some(secondary_ip)),
            "kill-switch filters must only target the secondary destination"
        );
    }

    #[test]
    fn remove_for_sid_drops_the_installed_filter_set() {
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("A", snap_full("Wi-Fi", "TAP"));
        orch.install_for_sid("A").unwrap();
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
        let removed = orch.remove_for_sid("A").unwrap();
        assert_eq!(removed, 2 + EXEMPT);
        assert!(api.wfp_filters.lock().unwrap().is_empty());
        assert!(orch.installed_sids().is_empty());
    }

    #[test]
    fn remove_for_sid_unknown_sid_is_idempotent() {
        let (_api, orch, _src, _rules, _audit) = fixture();
        let removed = orch.remove_for_sid("ghost").unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn empty_sid_is_rejected() {
        let (_api, orch, _src, _rules, _audit) = fixture();
        assert!(matches!(
            orch.install_for_sid(""),
            Err(OrchestratorError::EmptySid)
        ));
        assert!(matches!(
            orch.remove_for_sid(""),
            Err(OrchestratorError::EmptySid)
        ));
    }

    #[test]
    fn recompile_for_sid_replaces_filter_set() {
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("A", snap_full("Wi-Fi", "TAP"));
        orch.install_for_sid("A").unwrap();
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
        // filter count is rule-driven, not
        // binding-driven. Recompile picks up updated *rules*, not
        // updated bindings — switch the active rule book to a
        // single-rule shape to verify the recompile path replaces
        // the live filter set.
        _rules.set(rules_with_n_primary_ips(1));
        src.set("A", snap_primary_only("Ethernet"));
        let count = orch.recompile_for_sid("A").unwrap();
        assert_eq!(count, 1);
        let filters = api.wfp_filters.lock().unwrap();
        assert_eq!(filters.len(), 1);
        assert!(filters[0].user_sid.as_deref() == Some("A"));
    }

    #[test]
    fn recompile_with_unchanged_rules_touches_nothing() {
        //  — the window-free recompile: an apply that changes
        // nothing must be a no-op diff (no removes, no adds), never a
        // remove-then-reinstall of the identical set. One `Updated` audit
        // records the pass; the live WFP set is byte-identical.
        let (api, orch, src, _rules, audit) = fixture();
        src.set("A", snap_full("Wi-Fi", "TAP"));
        orch.install_for_sid("A").unwrap();
        let before: Vec<u64> = api
            .wfp_filters
            .lock()
            .unwrap()
            .iter()
            .map(|f| f.id.raw)
            .collect();
        assert!(!before.is_empty());

        let count = orch.recompile_for_sid("A").unwrap();
        assert_eq!(count, before.len(), "reports the full live set size");
        let after: Vec<u64> = api
            .wfp_filters
            .lock()
            .unwrap()
            .iter()
            .map(|f| f.id.raw)
            .collect();
        assert_eq!(
            after, before,
            "identical desired set → the installed filters are untouched"
        );
        let records = audit.snapshot();
        let last = records.last().expect("audit record");
        assert_eq!(last.kind, PerSidApplyAuditKind::Updated);
        assert!(
            last.message.contains("+0 -0"),
            "no-op diff is audited as such, got: {}",
            last.message
        );
    }

    #[test]
    fn recompile_with_rules_uses_the_supplied_snapshot_not_the_provider() {
        // activation dispatches BEFORE the active
        // pointer commits, so the provider (storage read) must NOT be
        // consulted when the caller hands the revision content. Model the
        // exact 0716 failure: provider says "no active rules" (pointer not
        // committed yet) while the dispatcher holds the new revision.
        let (api, orch, src, rules, _audit) = fixture();
        src.set("A", snap_primary_only("Ethernet"));
        rules.clear();

        // Storage-read path installs nothing (this WAS the 0716 bug's shape).
        assert_eq!(orch.recompile_for_sid("A").unwrap(), 0);
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);

        // Pass-through path installs the handed rules.
        let handed = rules_with_n_primary_ips(3);
        let count = orch.recompile_for_sid_with_rules("A", &handed).unwrap();
        assert_eq!(count, 3);
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
    }

    #[test]
    fn policy_apply_trigger_recompiles_for_console_fallback_sid_without_tray() {
        // a policy update from a GUI-only connection
        // (empty registry = dead tray subscription) must still recompile for
        // the console user; without the fallback it was silently skipped.
        use crate::ipc_handlers::providers::RoutePolicyApplyTrigger as _;
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("S-CONSOLE", snap_primary_only("Ethernet"));
        let registry = Arc::new(ActiveSidRegistry::new());

        // Without the fallback the trigger skips (pre-0716 behaviour).
        let bare =
            OrchestratorRoutePolicyApplyTrigger::new(Arc::clone(&orch), Arc::clone(&registry));
        bare.on_policy_changed("S-CONSOLE");
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);

        // With the fallback naming this SID, the recompile runs.
        let trigger =
            OrchestratorRoutePolicyApplyTrigger::new(Arc::clone(&orch), Arc::clone(&registry))
                .with_fallback_routing_sid(Arc::new(|| Some("S-CONSOLE".to_string())));
        trigger.on_policy_changed("S-CONSOLE");
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);

        // A different SID than the fallback still skips.
        trigger.on_policy_changed("S-OTHER");
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);
    }

    #[test]
    fn policy_apply_trigger_skips_a_routing_paused_sid() {
        // a policy edit by a PAUSED user must
        // not reinstall their filters (pause = no enforcement). Also fail-closed
        // to "paused" on a read error.
        use crate::ipc_handlers::providers::RoutePolicyApplyTrigger as _;
        use nrr_shared::ipc::IpcClientProfile;
        use std::sync::atomic::{AtomicBool, Ordering};
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("S-TRAY", snap_primary_only("Ethernet"));
        let registry = Arc::new(ActiveSidRegistry::new());
        registry.on_connect("S-TRAY", IpcClientProfile::TrayLightweight);

        // Paused → the trigger installs nothing even though the SID is tray-active.
        let paused = Arc::new(AtomicBool::new(true));
        let p = Arc::clone(&paused);
        let trigger =
            OrchestratorRoutePolicyApplyTrigger::new(Arc::clone(&orch), Arc::clone(&registry))
                .with_paused_check(Arc::new(move |_sid: &str| p.load(Ordering::SeqCst)));
        trigger.on_policy_changed("S-TRAY");
        assert_eq!(
            api.wfp_filters.lock().unwrap().len(),
            0,
            "a paused SID's filters must not be (re)installed by a policy edit"
        );

        // Un-paused → the same edit now recompiles.
        paused.store(false, Ordering::SeqCst);
        trigger.on_policy_changed("S-TRAY");
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);
    }

    #[test]
    fn verify_after_apply_confirms_live_and_detects_phantom() {
        // after an install, every
        // recorded id must be live in WFP (0 phantom); an id that was never
        // added is flagged as a phantom.
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("A", snap_primary_only("Ethernet"));
        let count = orch.install_for_sid("A").unwrap();
        let installed: Vec<WfpFilterId> = api
            .wfp_filters
            .lock()
            .unwrap()
            .iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(
            orch.verify_installed_filters_live("A", &installed, count),
            Some(0),
            "all installed filters are live in the engine",
        );
        // An id never added → phantom detected.
        let bogus = vec![WfpFilterId { raw: 0xDEAD_BEEF }];
        assert_eq!(
            orch.verify_installed_filters_live("A", &bogus, 1),
            Some(1),
            "an id not present in the live engine is a phantom",
        );
    }

    #[test]
    fn two_sids_have_independent_filter_sets() {
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("A", snap_full("Wi-Fi", "TAP"));
        src.set("B", snap_primary_only("Ethernet"));
        orch.install_for_sid("A").unwrap();
        orch.install_for_sid("B").unwrap();
        // filter count is rule-driven (2 ExactIp
        // rules in the fixture's primary set), not binding-driven.
        // Both SIDs see the same active rule book, so both get the
        // same filter count — what makes them independent is the
        // per-filter `user_sid` tag, not the count.
        assert_eq!(orch.filter_count_for("A"), 2 + EXEMPT);
        assert_eq!(orch.filter_count_for("B"), 2);
        let total = api.wfp_filters.lock().unwrap();
        assert_eq!(total.len(), 4 + EXEMPT);
        let a_filters: Vec<_> = total
            .iter()
            .filter(|f| f.user_sid.as_deref() == Some("A"))
            .collect();
        let b_filters: Vec<_> = total
            .iter()
            .filter(|f| f.user_sid.as_deref() == Some("B"))
            .collect();
        assert_eq!(a_filters.len(), 2 + EXEMPT);
        assert_eq!(b_filters.len(), 2);
    }

    #[test]
    fn reconcile_installs_new_sids_and_removes_departed_ones() {
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("A", snap_primary_only("Wi-Fi"));
        src.set("B", snap_primary_only("TAP"));

        // Initial reconcile from empty → A,B → both installed. Each
        // SID gets the rule-book-driven filter count (fixture = 2).
        orch.reconcile(&["A".into(), "B".into()]).unwrap();
        assert_eq!(orch.installed_sids(), vec!["A", "B"]);
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 4);

        // A drops out → only B.
        orch.reconcile(&["B".into()]).unwrap();
        assert_eq!(orch.installed_sids(), vec!["B"]);
        let filters = api.wfp_filters.lock().unwrap();
        assert_eq!(filters.len(), 2);
        assert!(filters.iter().all(|f| f.user_sid.as_deref() == Some("B")));
    }

    #[test]
    fn wire_orchestrator_to_registry_drives_install_remove_via_listener() {
        use nrr_shared::ipc::IpcClientProfile;
        let (api, orch, src, _rules, _audit) = fixture();
        src.set("A", snap_primary_only("Wi-Fi"));

        let registry = ActiveSidRegistry::new();
        wire_orchestrator_to_registry(Arc::clone(&orch), &registry);

        // M-1: only `TrayLightweight` connects fire the
        // routing-active listener. A `GuiInteractive` connect is
        // tracked but does NOT trigger filter installation. Filter
        // count is rule-driven (fixture = 2 ExactIp rules).
        registry.on_connect("A", IpcClientProfile::TrayLightweight);
        assert_eq!(orch.installed_sids(), vec!["A".to_string()]);
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);

        registry.on_disconnect("A", IpcClientProfile::TrayLightweight);
        assert!(orch.installed_sids().is_empty());
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    // ── Audit + multi-user fixture tests ────────────────────────────────

    #[test]
    fn install_emits_applied_audit_record() {
        let (_api, orch, src, _rules, audit) = fixture();
        src.set("A", snap_full("Wi-Fi", "TAP"));
        orch.install_for_sid("A").unwrap();
        let records = audit.snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sid, "A");
        assert_eq!(records[0].kind, PerSidApplyAuditKind::Applied);
        assert_eq!(records[0].filter_count, 2 + EXEMPT as u32);
        assert_eq!(records[0].message, "ok");
    }

    #[test]
    fn second_install_for_same_sid_emits_updated_kind() {
        let (_api, orch, src, _rules, audit) = fixture();
        src.set("A", snap_primary_only("Wi-Fi"));
        orch.install_for_sid("A").unwrap();
        // Same SID, different policy → next install is "Updated".
        src.set("A", snap_full("Wi-Fi", "TAP"));
        orch.install_for_sid("A").unwrap();
        let records = audit.snapshot();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, PerSidApplyAuditKind::Applied);
        assert_eq!(records[1].kind, PerSidApplyAuditKind::Updated);
        assert_eq!(records[1].filter_count, 2 + EXEMPT as u32);
    }

    #[test]
    fn remove_emits_withdrawn_audit_record() {
        let (_api, orch, src, _rules, audit) = fixture();
        src.set("A", snap_full("Wi-Fi", "TAP"));
        orch.install_for_sid("A").unwrap();
        orch.remove_for_sid("A").unwrap();
        let records = audit.snapshot();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].kind, PerSidApplyAuditKind::Withdrawn);
        assert_eq!(records[1].filter_count, 2 + EXEMPT as u32);
    }

    #[test]
    fn audit_kind_slugs_are_stable_for_telemetry() {
        // Slugs are part of the audit wire contract — locking them in
        // prevents accidental rename in future cleanup.
        assert_eq!(
            PerSidApplyAuditKind::Applied.slug(),
            "per-sid-policy-applied"
        );
        assert_eq!(
            PerSidApplyAuditKind::Updated.slug(),
            "per-sid-policy-updated"
        );
        assert_eq!(
            PerSidApplyAuditKind::Withdrawn.slug(),
            "per-sid-policy-withdrawn"
        );
        assert_eq!(PerSidApplyAuditKind::Failed.slug(), "per-sid-policy-failed");
    }

    /// Multi-user scenario: User A and User B simultaneously have GUI
    /// connections; their filters live in the same WFP session,
    /// distinguished by `user_sid`. When User A submits
    /// `RoutePolicyUpdate`, only A's filters are recompiled.
    #[test]
    fn two_users_concurrent_with_independent_recompile() {
        let (api, orch, src, _rules, audit) = fixture();
        src.set("A", snap_primary_only("Wi-Fi"));
        src.set("B", snap_full("Ethernet", "TAP-B"));
        orch.install_for_sid("A").unwrap();
        orch.install_for_sid("B").unwrap();
        assert_eq!(orch.installed_sids(), vec!["A", "B"]);
        // 2 rule-driven filters per SID, regardless
        // of bindings. B (snap_full) additionally carries the VPN-exempt permits.
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 4 + EXEMPT);

        // User A's recompile pass: bindings change but rules stay,
        // so the rule-driven filter set is unchanged. The lifecycle
        // path (remove + install) still runs end-to-end; what we
        // verify here is that B's filter set isn't disturbed.
        src.set("A", snap_full("Wi-Fi", "TAP-A"));
        orch.recompile_for_sid("A").unwrap();

        let filters = api.wfp_filters.lock().unwrap();
        let a_count = filters
            .iter()
            .filter(|f| f.user_sid.as_deref() == Some("A"))
            .count();
        let b_count = filters
            .iter()
            .filter(|f| f.user_sid.as_deref() == Some("B"))
            .count();
        assert_eq!(a_count, 2 + EXEMPT, "A's filters after recompile");
        assert_eq!(
            b_count,
            2 + EXEMPT,
            "B's filters preserved during A's recompile"
        );

        // Audit chain: a recompile of an already-installed SID is the
        // window-free MAKE-then-BREAK diff, so it surfaces as a
        // single `Updated` record — never a Withdrawn/Applied pair, because
        // the old filter set is no longer torn down before the new one lands.
        let records = audit.snapshot();
        let kinds: Vec<_> = records.iter().map(|r| (r.sid.as_str(), r.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                ("A", PerSidApplyAuditKind::Applied),
                ("B", PerSidApplyAuditKind::Applied),
                ("A", PerSidApplyAuditKind::Updated),
            ],
        );
    }

    /// RDP simulation: a user disconnects (their session goes idle) →
    /// orchestrator removes their filter set. Reconnect → reinstall.
    /// Validates the production lifecycle when an RDP user signs in,
    /// works for a while, signs out, and a different user signs in.
    #[test]
    fn rdp_user_lifecycle_install_remove_install_different_user() {
        use nrr_shared::ipc::IpcClientProfile;
        let (api, orch, src, _rules, audit) = fixture();
        src.set("RDP-USER-1", snap_primary_only("Wi-Fi"));
        src.set("RDP-USER-2", snap_full("Ethernet", "TAP"));

        let registry = ActiveSidRegistry::new();
        wire_orchestrator_to_registry(Arc::clone(&orch), &registry);

        // RDP-USER-1 connects. Filter count is rule-driven (fixture
        // = 2 ExactIp rules) regardless of `snap_primary_only`'s
        // binding shape.
        registry.on_connect("RDP-USER-1", IpcClientProfile::TrayLightweight);
        assert_eq!(orch.installed_sids(), vec!["RDP-USER-1".to_string()]);
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);

        // RDP-USER-1 disconnects.
        registry.on_disconnect("RDP-USER-1", IpcClientProfile::TrayLightweight);
        assert!(orch.installed_sids().is_empty());
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);

        // RDP-USER-2 connects from a different RDP session.
        registry.on_connect("RDP-USER-2", IpcClientProfile::TrayLightweight);
        assert_eq!(orch.installed_sids(), vec!["RDP-USER-2".to_string()]);
        // RDP-USER-2 = snap_full → armed None branch → +VPN-exempt permits.
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
        let filters = api.wfp_filters.lock().unwrap();
        assert!(filters
            .iter()
            .all(|f| f.user_sid.as_deref() == Some("RDP-USER-2")));
        drop(filters);

        // Audit shows the full lifecycle.
        let records = audit.snapshot();
        assert!(records
            .iter()
            .any(|r| r.sid == "RDP-USER-1" && r.kind == PerSidApplyAuditKind::Applied));
        assert!(records
            .iter()
            .any(|r| r.sid == "RDP-USER-1" && r.kind == PerSidApplyAuditKind::Withdrawn));
        assert!(records
            .iter()
            .any(|r| r.sid == "RDP-USER-2" && r.kind == PerSidApplyAuditKind::Applied));
    }

    /// Performance smoke at modest scale: 10 SIDs × 2 filters each.
    /// Validates the orchestrator does not silently drop filters when
    /// many users are active simultaneously, and that audit records
    /// every SID. Production performance ceiling (50 RDP × 100 rules
    /// = 5000 filters) is documented in TASKS_RU; smaller smoke test
    /// here confirms the linear scaling is correct at least at the
    /// small end.
    #[test]
    fn smoke_ten_sids_each_with_two_filters() {
        let (api, orch, src, _rules, audit) = fixture();
        for i in 0..10 {
            let sid = format!("S-1-5-21-{i:02}");
            src.set(&sid, snap_full("Wi-Fi", "TAP"));
            orch.install_for_sid(&sid).unwrap();
        }
        assert_eq!(orch.installed_sids().len(), 10);
        // 10 SIDs × snap_full (armed None branch) = 10 × (2 rule filters + VPN exempt).
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 10 * (2 + EXEMPT));
        // Every WFP filter has a non-None user_sid.
        assert!(api
            .wfp_filters
            .lock()
            .unwrap()
            .iter()
            .all(|f| f.user_sid.is_some()));
        // Every audit record is `Applied` (no failures, no updates).
        let records = audit.snapshot();
        assert_eq!(records.len(), 10);
        assert!(records
            .iter()
            .all(|r| r.kind == PerSidApplyAuditKind::Applied));
    }

    // ── Route before block ─────────────────────────────────────

    /// `is_destination_block` over an ENUMERATED filter (what the mock engine
    /// hands back) rather than a spec. Same predicate, different type.
    fn record_is_destination_block(f: &nrr_platform_api::types::WfpFilterRecord) -> bool {
        f.action == WfpAction::Block
            && (f.remote_ip.is_some() || f.remote_subnet.is_some() || f.remote_subnet_v6.is_some())
    }

    /// `is_app_only_block` over an ENUMERATED filter.
    fn record_is_app_only_block(f: &nrr_platform_api::types::WfpFilterRecord) -> bool {
        f.action == WfpAction::Block
            && f.app_pattern.is_some()
            && f.remote_ip.is_none()
            && f.remote_subnet.is_none()
            && f.remote_subnet_v6.is_none()
    }

    /// Two secondary `ExactIp` rules, so a coverage reconcile can grow the
    /// destination pin set from one address to two.
    fn rules_with_secondary_ips(ips: &[Ipv4Addr]) -> ActiveRulesSnapshot {
        let rules: Vec<CanonicalRule> = ips
            .iter()
            .enumerate()
            .map(|(i, ip)| CanonicalRule {
                id: RuleId(format!("r-sec-{i}")),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(*ip)),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            })
            .collect();
        ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::default(),
                secondary: CanonicalRuleSet::from_rules(rules),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        }
    }

    /// Fixture whose route-sync hook records how many filters were live in WFP
    /// at the instant it ran. A recorded `0` therefore proves the route pass
    /// ran BEFORE any pin reached the engine — the ordering under test, without
    /// a real route table or a real WFP engine.
    #[allow(clippy::type_complexity)]
    fn fixture_with_route_sync(
        resolution: Option<KillSwitchResolution>,
    ) -> (
        Arc<MockWindowsApi>,
        Arc<PerSidApplyOrchestrator>,
        Arc<ScriptedSource>,
        Arc<ScriptedRules>,
        Arc<Mutex<Vec<usize>>>,
    ) {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let observed: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        let hook = {
            let api = Arc::clone(&api);
            let observed = Arc::clone(&observed);
            let hook: RouteSyncHook = Arc::new(move || {
                let live = api
                    .wfp_filters
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .len();
                observed
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(live);
            });
            hook
        };
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
            .with_route_sync(hook),
        );
        (api, orch, source, rules, observed)
    }

    #[test]
    fn route_sync_runs_before_a_cold_install_lands_destination_pins() {
        let (api, orch, src, rules, observed) = fixture_with_route_sync(Some(full_ks_resolution()));
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 10)));
        src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

        orch.install_for_sid("S-1-5-21-A").unwrap();

        let live = api.wfp_filters.lock().unwrap().clone();
        assert!(
            live.iter().any(record_is_destination_block),
            "the install must have landed at least one destination-scoped block",
        );
        let calls = observed.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![0],
            "the route pass ran, and ran on an empty engine"
        );
    }

    #[test]
    fn route_sync_is_skipped_when_nothing_destination_scoped_is_blocked() {
        // A primary-only policy emits rule permits and no leak-guard at all —
        // no destination block, so the ordering hook must not fire and the
        // steady state costs nothing.
        let (_api, orch, src, rules, observed) = fixture_with_route_sync(None);
        rules.set(rules_with_n_primary_ips(1));
        src.set("S-1-5-21-A", snap_primary_only("Wi-Fi"));

        orch.install_for_sid("S-1-5-21-A").unwrap();

        assert!(
            observed.lock().unwrap().is_empty(),
            "no new destination block ⇒ no route sync",
        );
    }

    #[test]
    fn route_sync_runs_before_a_reconcile_pins_a_newly_covered_destination() {
        let (api, orch, src, rules, observed) = fixture_with_route_sync(Some(full_ks_resolution()));
        rules.set(rules_with_secondary_ips(&[Ipv4Addr::new(203, 0, 113, 10)]));
        src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
        orch.install_for_sid("S-1-5-21-A").unwrap();
        let after_install = api.wfp_filters.lock().unwrap().len();
        observed.lock().unwrap().clear();

        // The FQDN/app stores growing a destination is what the reconcile sees;
        // a second rule address is the deterministic stand-in for it.
        rules.set(rules_with_secondary_ips(&[
            Ipv4Addr::new(203, 0, 113, 10),
            Ipv4Addr::new(203, 0, 113, 11),
        ]));
        let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

        assert!(added > 0, "the reconcile must have grown the pin set");
        let calls = observed.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![after_install],
            "the route pass ran exactly once, before the new pins reached the engine",
        );
    }

    #[test]
    fn route_sync_is_skipped_when_a_reconcile_changes_nothing() {
        let (_api, orch, src, rules, observed) =
            fixture_with_route_sync(Some(full_ks_resolution()));
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 10)));
        src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
        orch.install_for_sid("S-1-5-21-A").unwrap();
        observed.lock().unwrap().clear();

        let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

        assert_eq!(added, 0, "coverage is unchanged");
        assert!(
            observed.lock().unwrap().is_empty(),
            "an unchanged reconcile must not drive the route pass",
        );
    }

    // ── Blocking-scope classification ──────────────────────────

    #[test]
    fn registry_marks_app_only_blocks_as_app_scoped_and_destination_blocks_as_not() {
        // The per-app pin blocks EVERY destination its process talks to, the
        // per-destination pin only the address it names. The drop detector
        // needs to tell them apart, so the published registry must too.
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let registry =
            Arc::new(crate::killswitch_drop_registry::KillswitchBlockFilterRegistry::new());
        let resolver = nrr_platform_api::MockAppPathResolver::new()
            .with("tg.exe", vec![std::path::PathBuf::from(r"C:\Apps\tg.exe")]);
        let orch = PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_app_resolver(Arc::new(resolver))
        .with_kill_switch_resolver(Arc::new(|_| Some(full_ks_resolution())))
        .with_killswitch_drop_registry(Arc::clone(&registry));

        // One secondary address rule (destination pin) + one secondary app
        // rule (app pin) — the exact shape of the  run.
        let secondary = CanonicalRuleSet::from_rules(vec![
            CanonicalRule {
                id: RuleId("r-ip".into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(Ipv4Addr::new(
                    203, 0, 113, 10,
                ))),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            },
            CanonicalRule {
                id: RuleId("r-app".into()),
                enabled: true,
                address_match: None,
                app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
                    pattern: nrr_domain::canonical::CanonicalAppPattern::Exact("tg.exe".into()),
                    include_child_processes: false,
                }),
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            },
        ]);
        rules.set(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::default(),
                secondary,
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        });
        source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
        orch.install_for_sid("S-1-5-21-A").unwrap();

        let live = api.wfp_filters.lock().unwrap().clone();
        let app_block = live
            .iter()
            .find(|f| record_is_app_only_block(f))
            .expect("the secondary app rule must have armed an app-scoped pin");
        let dest_block = live
            .iter()
            .find(|f| record_is_destination_block(f))
            .expect("the secondary address rule must have armed a destination pin");

        // Both halves stay role-verified — the learner's gate is unchanged.
        assert!(registry.contains(app_block.id.raw));
        assert!(registry.contains(dest_block.id.raw));
        // Only the app-only block is app-scoped.
        assert!(registry.is_app_scoped(app_block.id.raw));
        assert!(!registry.is_app_scoped(dest_block.id.raw));
    }
}

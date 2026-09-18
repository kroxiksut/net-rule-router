//! [`PerSidApplyOrchestrator`] itself — the struct definition and the
//! resolver/hook type aliases wired into it. Behaviour lives in `builder`
//! (construction), `plan` (compute) and `apply` (install/remove); this is
//! only the shape of what those carry.
//!
//! Fields are `pub(super)`: every field was private-to-the-defining-module
//! before the split, and `plan`/`apply`/`builder`/`posture`/`shadow_compare`
//! are now siblings rather than the defining module itself, so the
//! visibility widens by exactly one module — the whole cost of the split.

use super::*;

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

/// Answers what policy may do about IPv6 for one SID's bindings this pass.
///
/// A resolver rather than a value because the answer changes with the links:
/// a tunnel that comes up carrying IPv6 turns a family that could only be
/// blocked into one that can be steered. Defaults to
/// [`Ipv6Guard::Off`][crate::enforcement_planner::Ipv6Guard::Off], which is the
/// shape from before the family existed; production resolves it through the
/// route coordinator.
pub type Ipv6GuardResolver =
    Arc<dyn Fn(&str) -> crate::enforcement_planner::Ipv6Guard + Send + Sync>;

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
pub(super) const UNRESOLVED_HOST_RESOLVE_CAP: usize = 64;

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
    pub(super) apply_locks: Mutex<std::collections::HashMap<String, Arc<Mutex<()>>>>,
    /// "Has the stop teardown begun?" A filter added behind it outlives the
    /// process — the WFP session is non-dynamic, so nothing takes it down when
    /// we exit. Injected rather than read from the static directly so a test
    /// can flip it for itself alone.
    pub(super) teardown_gate: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Per-SID fingerprint of the last input the neutral-plan shadow compare
    /// actually ran on. The compare re-derives the whole plan and lowers it —
    /// measured at seconds inside a pass that fires every 30 s — to produce one
    /// log line. On unchanged input that line says exactly what it said last
    /// time, so the work is skipped and only a real change is re-evidenced.
    ///
    /// Windows-only, like the comparison it serves: off-Windows there is no WFP
    /// filter set to compare against, and an ungated field is dead code that
    /// only the Linux build reports.
    #[cfg(windows)]
    pub(super) shadow_compare_seen: Mutex<std::collections::HashMap<String, u64>>,
    /// Last per-band breakdown logged for a SID, so the composition line is
    /// written when the SET CHANGES rather than on every recompute — the same
    /// dedup-on-content rule the other periodic lines follow.
    pub(super) standing_volume_last: Mutex<std::collections::HashMap<String, String>>,
    pub(super) session: Arc<WfpSession>,
    pub(super) policy_source: Arc<dyn RoutePolicySource>,
    pub(super) rules_provider: Arc<dyn RulesProvider>,
    pub(super) fqdn_cache: Arc<dyn FqdnCacheLookup>,
    /// App-routing via observation — observed app→IP map the
    /// codegen reads for `Application` rules. Defaults to an empty in-memory
    /// store (app rules then route nothing) until production wires the live
    /// store fed by the connection observer via [`Self::with_app_observations`].
    pub(super) app_observations: Arc<dyn AppObservationLookup>,
    /// resolves an `Application` rule's exe name/glob to concrete
    /// on-disk exe paths so the codegen can emit real per-app `ALE_APP_ID`
    /// filters. Defaults to a [`nrr_platform_api::NoopAppPathResolver`]
    /// (app rules then resolve nothing — surfaced as
    /// [`crate::wfp_codegen::CodegenDiagnostic::AppUnresolved`] rather than a
    /// silent apply-skip) until production wires a real resolver via
    /// [`Self::with_app_resolver`].
    pub(super) app_resolver: Arc<dyn nrr_platform_api::AppPathResolver>,
    pub(super) audit: Arc<dyn PerSidApplyAudit>,
    pub(super) failure_mode: FilterFailureModeSource,
    /// resolves the secondary interface LUID +
    /// exemptions the kill-switch needs. Defaults to "unresolved" →
    /// kill-switch off, so the feature is inert until production wires a
    /// real resolver via [`Self::with_kill_switch_resolver`].
    pub(super) kill_switch_resolver: KillSwitchResolver,
    pub(super) ipv6_guard_resolver: Ipv6GuardResolver,
    /// fail-closed exemptions resolver. Used when the
    /// secondary is unresolvable yet the user requested a kill-switch with
    /// the fail-closed posture: mode B then blocks *all* egress except these
    /// exemptions (primary local subnets + any cached VPN-server IPs) so the
    /// box stays manageable and the tunnel can reconnect. Defaults to empty
    /// (loopback/link-local/broadcast are always exempt in the codegen).
    pub(super) fail_closed_exemptions_resolver: FailClosedExemptionsResolver,
    /// Proactive VPN-client exemption — verified VPN client exe
    /// paths merged into the kill-switch app-exemption set on every compute,
    /// so a known client is permitted through a block-all posture BEFORE its
    /// first drop of the session (rotating provider check IPs defeat the
    /// per-IP reactive exemption). `None` (default) contributes nothing.
    pub(super) vpn_client_apps_provider: Option<VpnClientAppsProvider>,
    /// Tears down live connections to a destination. Used on the activation
    /// edge so sockets that predate a new rule do not finish on the old link.
    /// `None` leaves the repair to the connection observer's reactive path.
    pub(super) stale_flow_reset:
        Option<Arc<dyn nrr_platform_api::fake_ip::stale_flows::StaleFlowReset>>,
    /// Rule hosts this apply could not enforce for lack of a confirmed
    /// address. `None` (default) drops them, which is the pre-existing
    /// behaviour: the host is enforced whenever something else resolves it.
    pub(super) unresolved_hosts_sink: Option<UnresolvedHostsSink>,
    pub(super) state: Mutex<HashMap<String, PerSidFilterSet>>,
    /// persists installed filter ids so a
    /// hard-killed prior instance's orphaned filters can be reaped BY ID at the
    /// next start (robust against an unreliable WFP enumerate). `None` disables
    /// persistence (tests / degraded boot).
    pub(super) ledger: Option<Arc<crate::wfp_filter_ledger::WfpFilterLedger>>,
    /// shared status the codegen's `AppUnresolved`
    /// diagnostics are published into on every filter compute, so the
    /// `SnapshotInitial` handler can surface a GUI banner listing app rules
    /// that resolved to no exe path (and are therefore unenforced). `None`
    /// leaves the diagnostics INFO-logged only (tests / degraded boot).
    pub(super) app_enforcement_status: Option<crate::app_enforcement_status::AppEnforcementStatus>,
    /// shared count of secondary IPs the "smart"
    /// kill-switch excluded this compute (census-shared with direct hosts).
    /// Written on every filter compute; read by `SnapshotInitial` for the GUI
    /// warning. `None` (default) = log-only.
    pub(super) shared_ip_exemption_status:
        Option<crate::app_enforcement_status::SharedIpExemptionStatus>,
    /// OS resolver-cache flush, fired on the
    /// fail-closed block-all arming/disarming EDGE (see
    /// [`Self::note_block_all_state`]). Names resolved before the block armed
    /// sit in the OS resolver cache, so the DNS observer never sees them and
    /// their suffix/zone permits are never built. Defaults to
    /// [`nrr_platform_api::NoopDnsCacheControl`]; production wires the real
    /// per-OS mechanism via [`Self::with_dns_cache_control`].
    pub(super) dns_cache_control: Arc<dyn nrr_platform_api::DnsCacheControlPort>,
    /// Per-SID latch behind the arming-edge detection for the flush above.
    /// `true` = the last compute for this SID produced a fail-closed
    /// block-all set. Only transitions trigger a flush — the leak-guard
    /// reconcile recomputes every few seconds and must not flush steadily.
    pub(super) block_all_flush_state: Mutex<HashMap<String, bool>>,
    /// Per SID, the highest standing filter volume already reported above the
    /// alarm line. The reconcile recomputes every few seconds, so the watchdog
    /// speaks only on a NEW peak — a plain rising edge went quiet after the
    /// first crossing and had nothing to say about the six hours that followed.
    /// Alarm, never self-healing: unpinning a guard would trade the BFE crash
    /// for a leak.
    pub(super) standing_volume_alarmed: Mutex<std::collections::HashMap<String, usize>>,
    /// Who is asking for a cut the packet layer cannot scope to one user.
    /// The WFP packet layers carry no `ALE_USER_ID`, so one principal's
    /// block-all (or IPv6 cut) takes ICMP and IPv6 away from everyone logged
    /// in. The others are told rather than left to discover it.
    pub(super) machine_wide_cut_state: Mutex<HashMap<String, bool>>,
    /// Last reported set of rules this SID names on BOTH routes, as a
    /// fingerprint. The state persists until the user resolves it, so the
    /// notice fires on a CHANGE — repeating it on every apply would teach them
    /// to dismiss it unread.
    pub(super) cross_set_duplicate_state: Mutex<HashMap<String, String>>,
    /// App-match patterns already announced to this SID. A rule is only news
    /// the first time it is delivered; every later apply carries it again.
    pub(super) announced_app_rules: Mutex<HashMap<String, std::collections::BTreeSet<String>>>,
    /// Push bus for those notices. `None` in tests that do not care.
    pub(super) events: Option<Arc<crate::ipc_handlers::event_bus::EventBus>>,
    /// last LOGGED kill-switch posture per SID. The
    /// leak-guard reconcile recomputes every ~5 s, and repeating the armed /
    /// fail-closed posture line each tick flooded the operational NDJSON
    /// (hundreds of identical warns per run — they alone would exhaust the
    /// 5 MiB diagnostic-archive log cap). Posture logs fire at full level on
    /// a CHANGE (see [`PostureLogEvent::Transition`]) and, for callers that
    /// opt in, on a periodic heartbeat while the posture persists (see
    /// [`PostureLogEvent::Heartbeat`]); steady-state re-derivations between
    /// those fire at `debug`.
    pub(super) posture_log_state: Mutex<HashMap<String, PostureLogLatch>>,
    /// When the provider yields a context whose scope is enabled, the codegen is
    /// augmented: the fake pool is permitted, and the real IPs a fake-routed host
    /// shares with a directly-routed one lose their `/32` permit (fed into the
    /// secondary denylist). Resolved fresh on EVERY compute (see
    /// [`FakeIpContextProvider`]); the default provider yields `None`, leaving
    /// fake-IP out of the plan. Production wires this via
    /// [`Self::with_fake_ip_context_provider`] from the fake-IP setting, the
    /// enforcement mode, and the live stack state.
    pub(super) fake_ip_context: FakeIpContextProvider,
    /// session registry of destinations positively
    /// established as DIRECT (non-rule) hosts: a Mode-B steered direct answer,
    /// or an FCrDNS forward-confirmed non-rule name. Under the catch-all
    /// block-all each earns an ALE exempt + packet permit (minus anything
    /// secondary-destined) so plain primary-path sites survive the posture.
    /// `None` (default) keeps the strict block-all.
    pub(super) known_direct: Option<Arc<crate::known_direct::KnownDirectRegistry>>,
    /// shared "block-all armed" posture for the GUI banner
    /// (see [`crate::app_enforcement_status::BlockAllPostureStatus`]). Written
    /// on every block-all transition edge. `None` (default) = log-only.
    pub(super) block_all_posture_status:
        Option<crate::app_enforcement_status::BlockAllPostureStatus>,
    /// Per-SID latch for the WIDER "the additional link is unresolved and the
    /// guard is blocking" posture — armed for the per-IP block set too, not
    /// just the catch-all. Feeds
    /// [`crate::app_enforcement_status::FailClosedPostureStatus`], which the
    /// DNS handler and the hostname seeder read: while it is armed the guard
    /// can only block addresses it already knows, so neither of them may act as
    /// if a rule host were covered.
    pub(super) fail_closed_state: Mutex<HashMap<String, bool>>,
    /// Shared publication of the latch above. `None` (default) = log-only.
    pub(super) fail_closed_posture_status:
        Option<crate::app_enforcement_status::FailClosedPostureStatus>,
    /// Reactive VPN-endpoint learning — publishes the WFP spec ids of the
    /// CURRENT kill-switch/fail-closed BLOCK filters so the connection
    /// observer's learner can role-verify a drop before trusting it (see
    /// [`crate::killswitch_drop_registry::KillswitchBlockFilterRegistry`]).
    /// `None` (default) leaves the registry unpublished — the consumer-side
    /// gate then stays permanently closed.
    pub(super) killswitch_drop_registry:
        Option<Arc<crate::killswitch_drop_registry::KillswitchBlockFilterRegistry>>,
    /// Per-SID bookkeeping behind [`Self::killswitch_drop_registry`]: each
    /// compute publishes only the SID it just derived, but the registry's
    /// `publish` replaces its ENTIRE set — so this tracks every SID's most
    /// recent kill-switch/fail-closed Block id set and the registry is always
    /// republished with their union, or a concurrently-active second SID's
    /// filters would be evicted the moment the first SID's next reconcile runs.
    pub(super) killswitch_block_ids_by_sid: Mutex<HashMap<String, KillswitchBlockIds>>,
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
    pub(super) route_sync: Option<RouteSyncHook>,
    /// Queue drained by the resume watchdog. A fail-closed posture that persists
    /// past a heartbeat asks here for a fresh binding resolution — the machine
    /// may have woken into a network where the bound tunnel adapter is gone.
    pub(super) rebind_requests: Option<Arc<crate::power_resume::RebindRequests>>,
}

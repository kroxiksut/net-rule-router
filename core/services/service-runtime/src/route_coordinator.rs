//! secondary-route coordinator.
//!
//! Ties [`crate::route_codegen`] (rules → desired routes) to
//! [`crate::route_reconciler`] (desired → system route table) for the
//! **active console-session user** (Free single-active-user model — see
//! `route_reconciler` module doc). The wiring layer
//! ([`crate::runtime_deps`] in `nrr-windows-service`) resolves *which*
//! user is active and the secondary adapter target, then calls
//! [`SecondaryRouteCoordinator::recompute_for`] on every trigger (active
//! user changed, that user's rules changed, secondary availability
//! changed, FQDN cache warmed).
// The log-once latches live in `route_coordinator::notice_latches`; the
// kill-switch / fail-closed exemption sets in `::exemptions`. Same
// inherent impl, split across files.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nrr_domain::ipv4_network::Ipv4Network;
use nrr_domain::RouteBehaviorMode;
use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::device_status::NetworkDeviceStatusPort;
use nrr_platform_api::reachability::ReachabilityProbe;
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::{classify_availability, AdapterAvailability, PlatformError, RouteEntry};

use crate::app_observation_lookup::{AppObservationLookup, AppObservationStore};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::killswitch_codegen::{FailClosedExemptions, KillSwitchResolution};
use crate::per_sid_orchestrator::{
    PerSidBehaviorMode, PerSidBinding, RoutePolicySource, RulesProvider,
};
use crate::route_codegen::{generate_routes, SecondaryRouteTarget};
use crate::route_reconciler::{
    bootstrap_server_ips, primary_local_subnets, RouteReconcileDelta, SecondaryRouteReconciler,
};
use crate::secondary_liveness::SecondaryLivenessTracker;

mod binding_resolver;
mod exemptions;
mod notice_latches;

// Re-exported at the old path: `adapter_binding_matches` and
// `adapter_entry_binding_matches` are called from `production_handlers_misc`
// as `route_coordinator::…`, and moving a file should not move a caller.
use binding_resolver::{
    adapter_answers_to_saved_name, binding_matches_live, derive_primary_target,
    derive_secondary_next_hop, diagnostic_tally, mac_anchor_id, preferred_display_name,
};
pub use binding_resolver::{adapter_binding_matches, adapter_entry_binding_matches};
// Read only by this module's tests, which sit in a sibling file and reach it
// through `super::`.
#[cfg(test)]
use binding_resolver::description_matches_display_name;

/// Resolved routing inputs for one principal (block 16.18.vpn): the active
/// behavior mode plus the usable primary/secondary targets. `secondary ==
/// None` means there is nowhere to route the tunnel set → tear everything
/// down. `primary` is only needed to carve mode-B exceptions back onto the
/// primary NIC; its absence is not an error in mode A.
#[derive(Debug, Clone, Copy)]
pub struct RouteResolution {
    pub mode: RouteBehaviorMode,
    pub primary: Option<SecondaryRouteTarget>,
    pub secondary: Option<SecondaryRouteTarget>,
}

/// 1:1 map of the per-SID behavior mode onto the codegen's
/// [`RouteBehaviorMode`] (mirrors
/// `per_sid_orchestrator::behavior_mode_for_codegen`, kept in sync).
fn route_behavior_mode(mode: PerSidBehaviorMode) -> RouteBehaviorMode {
    match mode {
        PerSidBehaviorMode::PreferPrimary => RouteBehaviorMode::PreferPrimary,
        PerSidBehaviorMode::PreferSecondaryWhenAvailable => {
            RouteBehaviorMode::PreferSecondaryWhenAvailable
        }
        PerSidBehaviorMode::StrictSecondaryFailClosed => {
            RouteBehaviorMode::StrictSecondaryFailClosed
        }
    }
}

/// reads the current routing scope: `true` =
/// service-driven (enforce the console user's policy continuously, even with
/// no tray connected — including from boot), `false` = app-driven (only while a
/// tray is connected). Backed live by the
/// `service_stability_config.rule_scope_service_driven` row so a settings
/// change takes effect on the next recompute without a service restart.
pub type RuleScopeProvider = Arc<dyn Fn() -> bool + Send + Sync>;

/// persist an auto-healed binding identity. Invoked by
/// `resolve_binding_target` when the stored adapter id was stale (e.g. the VPN
/// reinstalled/renamed its adapter → new GUID) and was auto-matched by saved
/// name to exactly ONE live adapter. Args: `(sid, role, healed_stable_id,
/// healed_display_name)`. It runs OUTSIDE the settings-DB lock — the binding was
/// loaded and the lock released before the heal — so the callback may safely
/// re-open the connection to write. Persisting the corrected id ends the
/// per-restart NOT-FOUND churn and makes the GUI reflect the real current
/// adapter (user decision : "autosave the healed binding").
pub type BindingHealPersistFn = Arc<dyn Fn(&str, &str, &str, &str) + Send + Sync>;

/// What one principal decided about LOCAL networks under the kill-switch:
/// networks to keep reachable on top of what the service discovers, and
/// discovered ones they refused. Read per resolve, so a change in Settings
/// takes effect on the next reconcile without a restart.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalNetworkPolicy {
    pub allowed: Vec<Ipv4Network>,
    pub refused: Vec<Ipv4Network>,
    /// The same answers keyed by the adapter they were given about, as
    /// `(adapter, allowed)`. A hypervisor switch renumbers its segment on every
    /// host reboot; without this the answer would apply to a network that no
    /// longer exists and the settings screen would promise what enforcement
    /// does not do.
    pub adapter_answers: Vec<(String, bool)>,
}

/// Reads [`LocalNetworkPolicy`] for a principal. A closure over the state DB at
/// the composition root; `None` means "no stored decisions", which is the
/// behaviour before the setting existed.
pub type LocalNetworkPolicyFn = Arc<dyn Fn(&str) -> LocalNetworkPolicy + Send + Sync>;

/// Persist one more identity for a binding that resolved correctly — the MAC
/// anchor learned on first resolve. Args: `(sid, role, anchor_stable_id)`.
/// Runs outside the settings-DB lock, like the heal callback.
pub type BindingAnchorPersistFn = Arc<dyn Fn(&str, &str, &str) + Send + Sync>;

/// persist the observed VPN bootstrap server IPs so the
/// kill-switch exemption survives a service restart. Invoked (best-effort) each
/// time the live route table yields a fresh, non-empty server-IP set — the same
/// place the in-memory `server_ip_cache` is refreshed. Runs OUTSIDE any recompute
/// lock, so the callback may re-open the state-DB connection to write. `None` in
/// tests / degraded boot (the cache stays in-memory only, as before).
pub type ServerIpPersistFn = Arc<dyn Fn(&[Ipv4Addr]) + Send + Sync>;

/// load the persisted VPN bootstrap server IPs at
/// startup, so the fail-closed exemption set is seeded even before the VPN
/// reconnects (the live in-memory cache is empty until the first observation).
/// Unioned with the live cache in [`SecondaryRouteCoordinator::fail_closed_exemptions`].
/// `None` in tests / degraded boot (no persisted seed, as before).
pub type ServerIpLoaderFn = Arc<dyn Fn() -> Vec<Ipv4Addr> + Send + Sync>;

/// Safe-disable (ROUTE-half) — what the route table should do for the effective
/// routing SID on a recompute, as reported by the pause predicate. Backed by the
/// persistent `routing_pause_state` flag (and, when paused, `RoutingStopPolicy`)
/// in storage, wired in `runtime_deps`. Consulted on EVERY recompute so a paused
/// user's routes are honoured via ANY re-drive path (active-user listener, DNS
/// warm-up / 30 s safety tick, apply-trigger, boot).
///
/// the predicate carries the stop-policy so the
/// 30 s safety tick no longer clobbers a `Persist` opt-in. On pause the route
/// half must match the WFP half's teardown flavour — a `Persist` user keeps the
/// `/32` secondary rule-routes (only NRR's overlays come down), a `Teardown` user
/// gets a full clear — otherwise the recompute gate silently deletes the `/32`
/// routes `teardown_routes` deliberately kept.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PausedRouteDisposition {
    /// Not paused — proceed with the normal recompute.
    Active,
    /// Paused, `RoutingStopPolicy::Teardown` — remove every owned route.
    ClearAll,
    /// Paused, `RoutingStopPolicy::Persist` — keep the `/32` secondary
    /// rule-routes and drop only NRR's overlays. Idempotent across re-drives.
    KeepSecondaryHosts,
}

/// Safe-disable (ROUTE-half) — the predicate the coordinator consults on every
/// recompute (see [`PausedRouteDisposition`]). The route coordinator reads this
/// rather than holding the pause coordinator, keeping the dependency acyclic —
/// the pause coordinator owns the route coordinator, not the reverse.
pub type PausedCheckFn = Arc<dyn Fn(&str) -> PausedRouteDisposition + Send + Sync>;

/// Owns the route reconciler and the inputs needed to recompute the
/// desired route set for the active console-session user.
/// per-probe ICMP-echo timeout. Short: a live tunnel
/// peer answers in a few ms; a dead one times out. The tracker's window (many
/// seconds of continuous failure) is what actually decides death, so this only
/// bounds a single probe.
const LIVENESS_PROBE_TIMEOUT: Duration = Duration::from_millis(1000);

pub struct SecondaryRouteCoordinator {
    reconciler: SecondaryRouteReconciler,
    api: Arc<dyn RouteTablePort>,
    rules_provider: Arc<dyn RulesProvider>,
    route_source: Arc<dyn RoutePolicySource>,
    fqdn_cache: Arc<dyn FqdnCacheLookup>,
    /// last successfully-derived tunnel next-hop per
    /// interface index. A gateway-less VPN's next-hop is derived from its
    /// catch-all routes; if those briefly vanish (e.g. a reconnect blip)
    /// derivation fails, so we fall back to this cache to keep routing instead
    /// of tearing everything down. Refreshed whenever derivation succeeds.
    next_hop_cache: Mutex<HashMap<u32, Ipv4Addr>>,
    /// last-known VPN server
    /// IPs (bootstrap host-route destinations) per secondary interface index.
    /// The VPN client may drop the bootstrap route while disconnected; caching
    /// the last-known set keeps the server exemption alive so the tunnel can
    /// reconnect through the kill-switch instead of deadlocking. Refreshed
    /// whenever the live route table yields a non-empty set.
    server_ip_cache: Mutex<HashMap<u32, Vec<Ipv4Addr>>>,
    /// Last-known connected subnets of the main link, per its interface index.
    /// Enumerating the route table can fail, and an EMPTY answer is not the
    /// same fact as "this machine has no LAN": armed on an empty set, the
    /// block-all cuts the local network, the printers and DHCP, and says
    /// nothing about it. Refreshed whenever the live table answers.
    local_subnet_cache: Mutex<HashMap<u32, Vec<(Ipv4Addr, u8)>>>,
    /// dedup state for the stale-binding
    /// auto-heal WARN. The heal re-fires on every reconcile while the stored
    /// GUID stays stale (e.g. the user runs a VPN whose adapter was reinstalled
    /// and never re-confirmed the binding in 'Interfaces & routes'), so without
    /// this the same WARN floods the operational log every poll. Keyed by
    /// `"{sid}|{role}"` → `(stale_id, healed_id)`; we emit the WARN only when
    /// that mapping first appears or changes, and stay quiet while it repeats.
    heal_logged: Mutex<HashMap<String, (String, String)>>,
    /// dedup twin of [`Self::heal_logged`] for the "bound adapter NOT
    /// FOUND" WARN. Keyed by `"{sid}|{role}"` → `(stale_id, live-set
    /// fingerprint)`; emit the WARN once per distinct state and stay quiet while
    /// a legitimately-absent secondary (VPN off) repeats every reconcile.
    /// Re-logs when the live adapter landscape actually changes.
    not_found_logged: Mutex<HashMap<String, (String, String)>>,
    /// latch backing the once-per-transition dedup of the
    /// "bound adapter found but NOT usable" WARN. Keyed by `"{sid}|{role}"` →
    /// the `stable_id` currently latched not-usable. A flapping adapter (e.g.
    /// a TAP instance cycling up/down) re-derives this same not-usable state
    /// every reconcile, which flooded the operational log (HW: 2120 repeats
    /// in one run) without this. Cleared the moment the binding resolves
    /// usable again (see [`Self::clear_not_usable`]), so the NEXT
    /// usable→not-usable transition warns again.
    not_usable_logged: Mutex<HashMap<String, String>>,
    /// Last enforcement status published per SID, so the push fires on change
    /// instead of at reconcile cadence.
    enforcement_status: Mutex<HashMap<String, String>>,
    /// When each SID was last told a tunnel is up with no additional route
    /// assigned, keyed by `"{sid}|{adapter}"`. Resolve runs at reconcile
    /// cadence — hundreds of times an hour — so without this the reminder would
    /// be a stream rather than a notice.
    unassigned_tunnel_notified: Mutex<HashMap<String, std::time::Instant>>,
    /// MAC anchors already handed to the persist callback this session, keyed by
    /// `"{sid}|{role}|{anchor}"`. The binding snapshot the resolve reads may be
    /// a cycle behind the write, so without this the same anchor would be
    /// written (and logged) on every reconcile until the reload catches up.
    anchor_persisted: Mutex<std::collections::HashSet<String>>,
    ///  — once-per-transition latch for the "UP but no derivable or
    /// cached next-hop" WARN, keyed `"{sid}|{role}"`. The state occurs in a
    /// tight burst while OpenVPN has brought the adapter Up but not yet
    /// installed its catch-all routes (HW: 55 identical WARNs in 2.2 s at
    /// first connect); resolution runs many times per second across reconcile,
    /// exemptions and probe paths, so without the latch each of them re-warns.
    /// Cleared whenever the binding resolves to a target again.
    no_next_hop_logged: Mutex<std::collections::HashSet<String>>,
    ///  — the ifindex most recently probed per SID by
    /// [`Self::probe_active_secondaries`]. When the binding stops resolving
    /// (adapter down mid-reconnect) the probe can no longer run, and the
    /// liveness tracker must drop that interface's failing run immediately —
    /// otherwise the stale window declares the tunnel dead the instant it
    /// comes back Up  HW: every VPN reconnect ended in a spurious
    /// DEAD + block-all). The tracker's own evidence-gap rule is the backstop;
    /// this makes the reset explicit and immediate.
    probed_ifindex: Mutex<HashMap<String, u32>>,
    /// live routing-scope read (service-driven vs
    /// app-driven). See [`RuleScopeProvider`].
    rule_scope_service_driven: RuleScopeProvider,
    /// optional callback to persist an auto-healed binding identity so
    /// the stale stored id does not resurface every restart. `None` in tests /
    /// degraded boot (heal stays in-memory only, as before). See
    /// [`BindingHealPersistFn`].
    binding_heal_persist: Option<BindingHealPersistFn>,
    /// optional write-through for a newly-learned identity of an
    /// already-correct binding (the MAC anchor). Separate from the heal
    /// callback because it must NOT move the binding to another adapter — it
    /// only widens what counts as the same one. See [`BindingAnchorPersistFn`].
    binding_anchor_persist: Option<BindingAnchorPersistFn>,
    /// The user's own answers about local networks (see [`LocalNetworkPolicyFn`]).
    local_networks: Option<LocalNetworkPolicyFn>,
    /// Asks the OS whether a bound adapter that vanished from the enumeration
    /// is actually gone or merely refusing to start. `None` keeps the older,
    /// coarser wording — which is correct, just less useful, so an unwired
    /// platform loses nothing it had.
    device_status: Option<Arc<dyn NetworkDeviceStatusPort>>,
    /// Push channel for [`Self::publish_enforcement_status`]. `None` in tests
    /// and in a degraded boot — the resolve then behaves exactly as before.
    events: Option<Arc<crate::ipc_handlers::event_bus::EventBus>>,
    /// optional write-through of the observed VPN server
    /// IPs (paired with [`Self::server_ip_cache`]) so the exemption survives a
    /// restart. See [`ServerIpPersistFn`].
    server_ip_persist: Option<ServerIpPersistFn>,
    /// optional loader for the persisted VPN server IPs,
    /// unioned into the fail-closed exemptions so they hold before the VPN
    /// reconnects. See [`ServerIpLoaderFn`].
    server_ip_loader: Option<ServerIpLoaderFn>,
    /// Safe-disable (ROUTE-half) — optional pause predicate. `None` in tests /
    /// when routing-pause is not wired: the recompute gate is a no-op and routes
    /// behave exactly as before. See [`PausedCheckFn`].
    paused_check: Option<PausedCheckFn>,
    /// active-probe liveness. `liveness` (shared with the
    /// probe tick + the setting) holds the per-adapter dead/alive verdict;
    /// `reachability_probe` runs the ICMP echo. Disabled (window 0, the default)
    /// or no probe wired → the liveness gate is a no-op and routing behaves
    /// exactly as before.
    liveness: Arc<SecondaryLivenessTracker>,
    reachability_probe: Option<Arc<dyn ReachabilityProbe>>,
    /// Destinations each application has been observed connecting to. An
    /// application rule has no address to resolve, so this is the only source
    /// of `/32` targets for it — and it must be the SAME store the filter
    /// codegen reads, or the route and the permit disagree about which
    /// interface the app's traffic uses. Defaults to an empty store (tests /
    /// degraded boot: application rules then produce no routes, as before).
    app_observations: Arc<dyn AppObservationLookup>,
    /// DNS-over-secondary — live read of the toggle. When it says
    /// `true`, each reconcile also emits `/32` routes for the public resolvers
    /// so the source-bound query sockets actually egress the tunnel. `None`
    /// (tests / degraded boot) behaves exactly as before: no such routes.
    dns_via_secondary: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Reactive VPN-endpoint learning — bounded, session-scoped, role-verified
    /// server IPs (see [`crate::vpn_endpoint_learning::LearnedVpnEndpoints`]
    /// and [`crate::conn_observation_consumer`]). Merged into both
    /// [`Self::kill_switch_exemptions`]'s and [`Self::fail_closed_exemptions`]'s
    /// `bootstrap_server_ips`, deduped against the route-observed set, so a
    /// learned endpoint gets exactly the same treatment as one seen on the
    /// wire. `None` (tests / degraded boot) leaves the exemption sets
    /// unchanged (today's behaviour).
    learned_vpn_endpoints: Option<Arc<crate::vpn_endpoint_learning::LearnedVpnEndpoints>>,
}

impl SecondaryRouteCoordinator {
    pub fn new(
        api: Arc<dyn RouteTablePort>,
        rules_provider: Arc<dyn RulesProvider>,
        route_source: Arc<dyn RoutePolicySource>,
        fqdn_cache: Arc<dyn FqdnCacheLookup>,
        rule_scope_service_driven: RuleScopeProvider,
    ) -> Self {
        Self {
            reconciler: SecondaryRouteReconciler::new(Arc::clone(&api)),
            api,
            rules_provider,
            route_source,
            fqdn_cache,
            next_hop_cache: Mutex::new(HashMap::new()),
            server_ip_cache: Mutex::new(HashMap::new()),
            local_subnet_cache: Mutex::new(HashMap::new()),
            heal_logged: Mutex::new(HashMap::new()),
            not_found_logged: Mutex::new(HashMap::new()),
            not_usable_logged: Mutex::new(HashMap::new()),
            anchor_persisted: Mutex::new(std::collections::HashSet::new()),
            enforcement_status: Mutex::new(HashMap::new()),
            unassigned_tunnel_notified: Mutex::new(HashMap::new()),
            no_next_hop_logged: Mutex::new(std::collections::HashSet::new()),
            probed_ifindex: Mutex::new(HashMap::new()),
            rule_scope_service_driven,
            binding_heal_persist: None,
            binding_anchor_persist: None,
            device_status: None,
            local_networks: None,
            events: None,
            server_ip_persist: None,
            server_ip_loader: None,
            paused_check: None,
            liveness: Arc::new(SecondaryLivenessTracker::new(0)),
            reachability_probe: None,
            app_observations: Arc::new(AppObservationStore::new()),
            dns_via_secondary: None,
            learned_vpn_endpoints: None,
        }
    }

    /// Share the DNS-over-secondary toggle so the reconcile emits the resolver
    /// `/32` routes the source-bound query sockets depend on. Chain before the
    /// coordinator is wrapped in `Arc`; pass the SAME flag the egress policy
    /// reads, or the socket and the route table disagree about the path.
    pub fn with_dns_via_secondary(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.dns_via_secondary = Some(flag);
        self
    }

    /// Share the reactive VPN-endpoint learner's bounded, role-verified server
    /// set so it is merged into the kill-switch/fail-closed exemption bands.
    /// Chain before the coordinator is wrapped in `Arc`. Without it, only
    /// route-observed bootstrap server IPs are exempted (today's behaviour).
    pub fn with_learned_vpn_endpoints(
        mut self,
        learned: Arc<crate::vpn_endpoint_learning::LearnedVpnEndpoints>,
    ) -> Self {
        self.learned_vpn_endpoints = Some(learned);
        self
    }

    /// Share the connection observer's app→destination store with the route
    /// codegen. Chain before the coordinator is wrapped in `Arc`. Pass the same
    /// store the per-SID filter orchestrator gets, so an application rule's
    /// route and its permit are built from one set of observations.
    pub fn with_app_observations(mut self, store: Arc<dyn AppObservationLookup>) -> Self {
        self.app_observations = store;
        self
    }

    /// Attaches the auto-heal persist callback (HW-0705). Chain before the
    /// coordinator is wrapped in `Arc`. Without it, an auto-healed binding is
    /// applied in-memory each reconcile but the stored id stays stale.
    pub fn with_binding_heal_persist(mut self, persist: BindingHealPersistFn) -> Self {
        self.binding_heal_persist = Some(persist);
        self
    }

    /// Wire the OS question "is this adapter gone, or here and broken?".
    /// Without it a missing adapter is reported as gone, which is what the
    /// product said before the port existed.
    #[must_use]
    pub fn with_device_status(mut self, port: Arc<dyn NetworkDeviceStatusPort>) -> Self {
        self.device_status = Some(port);
        self
    }

    /// Attaches the MAC-anchor persist callback. Chain before the coordinator is
    /// wrapped in `Arc`. Without it the anchor is recomputed every resolve and
    /// never stored, so a binding still depends on the GUID and the name alone.
    pub fn with_binding_anchor_persist(mut self, persist: BindingAnchorPersistFn) -> Self {
        self.binding_anchor_persist = Some(persist);
        self
    }

    /// Wire the user's local-network decisions. Chain before the coordinator is
    /// wrapped in `Arc`. Without it only the automatic answer applies.
    pub fn with_local_network_policy(mut self, read: LocalNetworkPolicyFn) -> Self {
        self.local_networks = Some(read);
        self
    }

    /// Share the push bus so the GUI and tray learn when policy stops being
    /// enforced. Chain before the coordinator is wrapped in `Arc`. Without it
    /// the state is logged and nothing else, which is how it stayed invisible.
    pub fn with_event_bus(mut self, events: Arc<crate::ipc_handlers::event_bus::EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// attach the VPN-server-IP persistence seam: a
    /// write-through `persist` (called whenever the live route table yields a
    /// fresh server-IP set) and a startup `loader` (unioned into the fail-closed
    /// exemptions). Chain before the coordinator is wrapped in `Arc`. Without it
    /// the server-IP set stays in-memory only and is lost on restart, as before.
    pub fn with_bootstrap_server_persistence(
        mut self,
        persist: ServerIpPersistFn,
        loader: ServerIpLoaderFn,
    ) -> Self {
        self.server_ip_persist = Some(persist);
        self.server_ip_loader = Some(loader);
        self
    }

    /// Attaches the routing-pause predicate (safe-disable ROUTE-half). Chain
    /// before the coordinator is wrapped in `Arc`. When it reports the effective
    /// routing SID paused, [`Self::recompute_active`] tears the route table down
    /// rather than (re)installing it, at the single choke point that covers every
    /// re-drive path. See [`PausedCheckFn`].
    pub fn with_pause_state(mut self, check: PausedCheckFn) -> Self {
        self.paused_check = Some(check);
        self
    }

    /// Attaches the Track-1 active-probe liveness (F7). `tracker` is shared with
    /// the probe tick (writer of verdicts) and the setting (writer of the
    /// window); `probe` runs the ICMP echo. Chain before the coordinator is
    /// wrapped in `Arc`. Without it the tracker stays disabled → `is_dead` is
    /// always false and the probe tick is a no-op, so behaviour is exactly as
    /// before.
    pub fn with_liveness_probe(
        mut self,
        tracker: Arc<SecondaryLivenessTracker>,
        probe: Arc<dyn ReachabilityProbe>,
    ) -> Self {
        self.liveness = tracker;
        self.reachability_probe = Some(probe);
        self
    }

    /// Recompute the route table for the **active console-session user**
    /// (Free single-active-user model). `active_sids` is the routing-active
    /// set from `ActiveSidRegistry`; in Free at most one is active. With
    /// none active the table is torn down (no user → no routes; M-1).
    ///
    /// Resolves the active user's secondary target (binding × live adapter
    /// info) itself, so the wiring layer only has to forward the trigger.
    /// Per-session routing for several concurrently-active users cannot be
    /// expressed in a machine-wide table; the first active SID owns it.
    pub fn recompute_active(
        &self,
        active_sids: &[String],
    ) -> Result<RouteReconcileDelta, PlatformError> {
        // Pick the routing user via the shared gate. `None` → tear down.
        let Some(sid) = self.effective_routing_sid(active_sids) else {
            tracing::info!(
                target: "nrr::route-coordinator",
                active_count = active_sids.len(),
                "no routing user to enforce (no tray, and either app-driven scope or no console session) — tearing down secondary routes",
            );
            return self.reconciler.clear();
        };
        // Safe-disable (ROUTE-half) — a paused routing user's routes must never
        // be (re)installed. This single choke point covers EVERY re-drive
        // (active-user listener, DNS warm-up / 30 s safety tick, apply-trigger,
        // boot). The stop-policy is honoured so the safety tick matches the
        // WFP half — `Teardown` full-clears, `Persist` keeps the `/32`
        // rule-routes and drops only NRR's overlays (idempotent), instead of
        // silently deleting the `/32`s `teardown_routes` kept.
        if let Some(check) = self.paused_check.as_ref() {
            match check(&sid) {
                PausedRouteDisposition::Active => {}
                PausedRouteDisposition::ClearAll => {
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        sid = %sid,
                        "routing paused for this user (teardown policy) — tearing down secondary routes",
                    );
                    return self.reconciler.clear();
                }
                PausedRouteDisposition::KeepSecondaryHosts => {
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        sid = %sid,
                        "routing paused for this user (persist policy) — keeping /32 rule-routes, dropping overlays only",
                    );
                    return self.teardown_keep_secondary_hosts();
                }
            }
        }
        if active_sids.is_empty() {
            tracing::debug!(
                target: "nrr::route-coordinator",
                sid = %sid,
                "no tray connected; service-driven scope → enforcing active console user's policy",
            );
        }
        // Per-cycle heartbeat — debug so it does not flood the log every
        // poll interval. State changes (routes added/removed, resolve
        // failures) still log loudly below.
        tracing::debug!(
            target: "nrr::route-coordinator",
            sid = %sid,
            active_count = active_sids.len(),
            "recompute_active for routing user",
        );
        let resolution = self.resolve(&sid);
        self.recompute_for(&sid, &resolution)
    }

    /// the SID whose policy is actually enforced for
    /// `active_sids`: the first connected-tray SID (M-1), or — under
    /// service-driven scope with no tray — the OS active console-session user
    /// (so a managed policy enforces even with no app running, from boot).
    /// `None` means "nothing to enforce" (app-driven with no tray, or no
    /// console session). SHARED by `recompute_active`, the FQDN seeder, the
    /// DNS-observation consumer, and the policy-change trigger so all four
    /// target the SAME user the route table is built for — otherwise
    /// ExactFqdn/Suffix/Zone rules never get seeded for the console user from
    /// boot and only ExactIp + a warm cache enforce.
    pub fn effective_routing_sid(&self, active_sids: &[String]) -> Option<String> {
        if let Some(s) = active_sids.first() {
            return Some(s.clone());
        }
        if (self.rule_scope_service_driven)() {
            return self.api.active_console_user_sid();
        }
        None
    }

    /// the SID SET whose WFP enforcement should be
    /// installed right now: every routing-active (tray-connected) SID, or —
    /// with no tray at all — the single effective routing user from
    /// [`Self::effective_routing_sid`] (console-session user under
    /// service-driven scope). Gives the WFP orchestrator the SAME no-tray
    /// fallback the route half has had since , so enforcement
    /// self-arms from boot / survives a dead tray subscription instead of
    /// waiting for a tray connect (0716 run 2: zero WFP applies all run).
    /// Multi-tray SIDs pass through unchanged (the fallback only fills an
    /// EMPTY set — it never overrides connected trays).
    pub fn effective_enforcement_sids(&self, tray_active: &[String]) -> Vec<String> {
        if !tray_active.is_empty() {
            return tray_active.to_vec();
        }
        self.effective_routing_sid(&[]).into_iter().collect()
    }

    /// unconditional teardown of every owned route,
    /// for graceful service stop. Unlike `recompute_active(&[])` this never
    /// falls back to the console user under service-driven scope: stopping the
    /// service must restore pristine networking in BOTH scopes.
    pub fn teardown(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconciler.clear()
    }

    /// graceful-stop teardown that KEEPS the secondary
    /// `/32` rule-routes and removes only NRR's overlays, so rule-matched hosts
    /// keep egressing the secondary adapter after the service stops. VPN-type-aware
    /// without probing: removing the overlays lets the OS route the rest to the
    /// primary (gateway-less VPN) or the VPN's own default (full-tunnel VPN). See
    /// [`SecondaryRouteReconciler::retain_secondary_hosts`].
    pub fn teardown_keep_secondary_hosts(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconciler.retain_secondary_hosts()
    }

    /// resolve the secondary (VPN)
    /// interface LUID for `sid`, or `None` when there is no usable secondary
    /// target right now or its LUID cannot be resolved.
    ///
    /// The WFP kill-switch pins this LUID as the egress condition of its
    /// permit half (`FWPM_CONDITION_IP_LOCAL_INTERFACE`). Returning `None`
    /// makes the orchestrator fail **open** (no kill-switch this cycle)
    /// rather than installing a permit whose interface never matches —
    /// which would black-hole the protected set. Reuses [`Self::resolve`],
    /// so the "no secondary" reason is already logged there.
    pub fn resolve_secondary_luid(&self, sid: &str) -> Option<u64> {
        let secondary = self.resolve(sid).secondary?;
        match self.api.interface_luid_for_index(secondary.interface_index) {
            Ok(luid) if luid != 0 => Some(luid),
            Ok(_) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    ifindex = secondary.interface_index,
                    "secondary interface resolved to a zero LUID — kill-switch stays off (fail-open)",
                );
                None
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    ifindex = secondary.interface_index,
                    "could not resolve secondary interface LUID for kill-switch; staying off (fail-open): {e:?}",
                );
                None
            }
        }
    }

    /// the active user's primary/secondary
    /// egress interface indexes, for labelling observed connections
    /// (primary = direct/provider, secondary = VPN). Reuses [`Self::resolve`];
    /// a role yields `None` when it is unbound / unresolvable.
    pub fn resolve_egress_ifindexes(&self, sid: &str) -> (Option<u32>, Option<u32>) {
        let r = self.resolve(sid);
        (
            r.primary.map(|t| t.interface_index),
            r.secondary.map(|t| t.interface_index),
        )
    }

    /// `sid`'s usable additional link, in the shape the external-address
    /// announcer consumes: interface index, the adapter's own IPv4 (what a
    /// source-bound probe socket binds to) and its human-readable description.
    ///
    /// Reuses [`Self::resolve`] so "usable" means exactly what it means
    /// everywhere else — including the liveness gate: a tunnel the probe has
    /// declared dead is not a link whose external address is worth reporting.
    /// `None` while the secondary is unbound, unresolvable or has no IPv4.
    pub fn resolve_secondary_link(
        &self,
        sid: &str,
    ) -> Option<crate::secondary_external_address::SecondaryLink> {
        let target = self.resolve(sid).secondary?;
        let infos = self.api.get_adapter_infos().ok()?;
        let info = infos.iter().find(|i| i.index == target.interface_index)?;
        Some(crate::secondary_external_address::SecondaryLink {
            sid: sid.to_string(),
            interface_index: target.interface_index,
            source_ipv4: info.ipv4_addresses.first().copied()?,
            adapter_name: info.description.clone(),
        })
    }

    /// The active user's primary/secondary egress SOURCE addresses (the
    /// adapters' own IPv4 unicast addresses), for binding sockets that must
    /// leave over a specific role's link — the fake-IP relay dials with these.
    /// A role yields `None` when it is unbound, unresolvable, or its adapter
    /// currently has no IPv4 address.
    /// Interface index of the user's usable PRIMARY link, or `None` while it is
    /// unbound or unresolvable. Callers that must send over the link the policy
    /// routes traffic over — rather than over whichever link owns the OS default
    /// route — ask this.
    pub fn resolve_primary_interface_index(&self, sid: &str) -> Option<u32> {
        self.resolve(sid).primary.map(|t| t.interface_index)
    }

    pub fn resolve_egress_source_ips(&self, sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        let r = self.resolve(sid);
        let infos = match self.api.get_adapter_infos() {
            Ok(infos) => infos,
            Err(_) => return (None, None),
        };
        let source_of = |target: Option<SecondaryRouteTarget>| {
            target.and_then(|t| {
                infos
                    .iter()
                    .find(|i| i.index == t.interface_index)
                    .and_then(|i| i.ipv4_addresses.first().copied())
            })
        };
        (source_of(r.primary), source_of(r.secondary))
    }

    /// Resolve `sid`'s routing inputs (mode + primary/secondary targets) from
    /// its per-SID route policy and the live adapters. Logs WHY whenever a
    /// target can't be resolved — these silent exits once made the route side
    /// invisible in the log when "no route" was reported.
    fn resolve(&self, sid: &str) -> RouteResolution {
        let Some(policy) = self.route_source.load_for_sid(sid) else {
            tracing::info!(
                target: "nrr::route-coordinator",
                sid = %sid,
                "no route policy for this user — no secondary routes will be applied",
            );
            // From outside this is indistinguishable from a working product: the
            // service runs, the tray is green, and nothing is routed. Acceptance
            // run 19 spent ten minutes in exactly this state (339 log lines, zero
            // filters) with no way for the user to see it.
            self.publish_enforcement_status(sid, "no-policy", "", Vec::new());
            return RouteResolution {
                mode: RouteBehaviorMode::PreferPrimary,
                primary: None,
                secondary: None,
            };
        };
        let mode = route_behavior_mode(policy.mode);
        let infos = match self.api.get_adapter_infos() {
            Ok(i) => i,
            Err(e) => {
                self.publish_enforcement_status(sid, "adapters-unreadable", "", Vec::new());
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "adapter enumeration failed; cannot resolve route targets: {e:?}",
                );
                return RouteResolution {
                    mode,
                    primary: None,
                    secondary: None,
                };
            }
        };
        let secondary = match policy.secondary.as_ref() {
            Some(b) => {
                let raw = self.resolve_binding_target(sid, b, &infos, "secondary");
                self.gate_secondary_on_liveness(sid, raw)
            }
            None => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "NO SECONDARY ADAPTER BOUND — assign primary+secondary in 'Interfaces & routes' and apply (needs elevation). Without a secondary target nothing is routed out the secondary NIC.",
                );
                self.offer_unassigned_tunnel(sid, &infos);
                None
            }
        };
        // Primary carries mode-A's `/2` counter-overlay (unmatched → real link,
        // not the tunnel) and mode-B's exception `/32`s.
        let mut primary = policy
            .primary
            .as_ref()
            .and_then(|b| self.resolve_binding_target(sid, b, &infos, "primary"));
        // Footgun fix: the common setup binds ONLY the secondary (VPN). Without
        // a primary, mode A's counter-overlay can't be emitted and unmatched
        // traffic silently rides the VPN's redirect. Derive the real primary
        // from the OS default route so "direct" actually routes direct.
        if primary.is_none() {
            if let Some(sec) = secondary.as_ref() {
                let routes = self.api.get_ip_forward_table().unwrap_or_default();
                match derive_primary_target(&routes, sec.interface_index) {
                    Some(derived) => {
                        tracing::info!(
                            target: "nrr::route-coordinator",
                            sid = %sid,
                            ifindex = derived.interface_index,
                            gateway = %derived.gateway,
                            "no primary adapter bound — derived the primary from the OS default route (unmatched traffic will egress the real link, not the tunnel)",
                        );
                        primary = Some(derived);
                    }
                    None => {
                        tracing::warn!(
                            target: "nrr::route-coordinator",
                            sid = %sid,
                            secondary_ifindex = sec.interface_index,
                            "no primary adapter bound and no OS default route to derive one — in 'direct' mode unmatched traffic stays on the secondary (VPN). Bind a primary adapter in 'Interfaces & routes'.",
                        );
                        // Nothing the service can do about this one: without a
                        // main link there is nowhere to send what the rules do
                        // not route, so the user has to name one.
                        self.publish_enforcement_status(
                            sid,
                            "no-primary-route",
                            "primary",
                            Vec::new(),
                        );
                    }
                }
            }
        }
        RouteResolution {
            mode,
            primary,
            secondary,
        }
    }

    /// Teach the binding the MAC of the adapter it just resolved to, so a later
    /// GUID and ifindex change (Wi-Fi or Bluetooth after sleep, a NIC that came
    /// back on another port) is recognised directly instead of relying on the
    /// name heal — which needs the name to be both unchanged and unique.
    ///
    /// Skipped for adapters whose MAC rotates with their GUID (see
    /// [`mac_anchor_id`]) and for a binding that already knows it, so the steady
    /// state costs one string compare per reconcile and no write.
    fn remember_mac_anchor(
        &self,
        sid: &str,
        role: &str,
        binding: &PerSidBinding,
        info: &AdapterInfo,
    ) {
        let Some(anchor) = mac_anchor_id(info) else {
            return;
        };
        if binding.stable_id.eq_ignore_ascii_case(&anchor)
            || binding
                .known_stable_ids
                .iter()
                .any(|id| id.eq_ignore_ascii_case(&anchor))
        {
            return;
        }
        let Some(persist) = self.binding_anchor_persist.as_ref() else {
            return;
        };
        if !self.note_anchor_once(sid, role, &anchor) {
            return;
        }
        tracing::info!(
            target: "nrr::route-coordinator",
            sid = %sid,
            role = role,
            anchor = %anchor,
            adapter = %preferred_display_name(info),
            "remembered the adapter's MAC as a second identity for this binding",
        );
        persist(sid, role, &anchor);
    }

    /// The subnets that belong to the ADDITIONAL route itself — the tunnel's own
    /// interior.
    ///
    /// Read by the fake-IP answerer, which must never substitute a virtual
    /// address for one of these: they are reachable only from inside the tunnel,
    /// and a virtual address would send the caller to our TUN instead (the VPN
    /// client's own authorization endpoint is exactly such an address).
    pub fn publish_secondary_subnets(&self, sid: &str) {
        crate::secondary_subnets::global_secondary_subnets()
            .publish(self.secondary_local_networks(sid));
    }

    pub fn secondary_local_networks(&self, sid: &str) -> Vec<Ipv4Network> {
        let Some(secondary) = self.resolve(sid).secondary else {
            return Vec::new();
        };
        let routes = match self.api.get_ip_forward_table() {
            Ok(routes) => routes,
            Err(e) => {
                // Silence here reads downstream as "this link has no local
                // networks", which is a different statement entirely.
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "route table could not be read; reporting no local networks for the additional link: {e:?}",
                );
                return Vec::new();
            }
        };
        primary_local_subnets(&routes, secondary.interface_index)
            .into_iter()
            .filter_map(|(net, prefix)| Ipv4Network::new(net, prefix))
            .collect()
    }

    /// The local networks this principal's kill-switch can discover on its own:
    /// the main link's connected subnets and the host side of hypervisor
    /// adapters, each with the adapter it belongs to and whether it is the main
    /// link's. The settings screen lists exactly this, so what the user ticks
    /// and what the enforcement exempts are derived from one enumeration.
    pub fn discovered_local_networks(&self, sid: &str) -> Vec<(Ipv4Network, String, bool)> {
        let resolution = self.resolve(sid);
        let routes = match self.api.get_ip_forward_table() {
            Ok(routes) => routes,
            Err(e) => {
                // The settings screen lists exactly this, so an empty answer is
                // an empty screen. Say why rather than showing the user a
                // machine that appears to have no local networks.
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "route table could not be read; the local-networks screen will show nothing: {e:?}",
                );
                return Vec::new();
            }
        };
        let Ok(adapters) = self.api.get_adapter_infos() else {
            return Vec::new();
        };
        let name_of = |ifindex: u32| {
            adapters
                .iter()
                .find(|info| info.index == ifindex)
                .map(|info| preferred_display_name(info).to_string())
                .unwrap_or_default()
        };
        let mut out: Vec<(Ipv4Network, String, bool)> = Vec::new();
        if let Some(primary) = resolution.primary {
            for (net, prefix) in primary_local_subnets(&routes, primary.interface_index) {
                if let Some(network) = Ipv4Network::new(net, prefix) {
                    out.push((network, name_of(primary.interface_index), true));
                }
            }
        }
        for info in adapters
            .iter()
            .filter(|info| Some(info.index) != resolution.secondary.map(|s| s.interface_index))
            .filter(|info| nrr_platform_api::adapters::is_virtual_machine_adapter(info))
        {
            for (net, prefix) in primary_local_subnets(&routes, info.index) {
                let Some(network) = Ipv4Network::new(net, prefix) else {
                    continue;
                };
                if out.iter().any(|(found, _, _)| *found == network) {
                    continue;
                }
                out.push((network, preferred_display_name(info).to_string(), false));
            }
        }
        out
    }

    /// Settle which LOCAL networks stay reachable while the kill-switch blocks
    /// everything else.
    ///
    /// A kill-switch exists to stop traffic escaping to the provider instead of
    /// the tunnel. Traffic to a hypervisor's host-only segment never leaves
    /// this machine, so blocking it protects nothing and takes the user's
    /// virtual machines away with the tunnel. The tunnel's own subnet is
    /// excluded, and a VPN adapter is never mistaken for a hypervisor one —
    /// both live in RFC1918 space, and that is exactly the confusion this must
    /// not make.
    ///
    /// The user has the last word in both directions: a network they named
    /// themselves is added (a hypervisor in NAT mode creates no host interface,
    /// so nothing here can discover it), and a network they refused is removed
    /// even if it was discovered automatically.
    /// Mark the rows the reconciler knows are ours.
    ///
    /// The route-table FFI cannot tell — it reports `is_ours = false` for
    /// everything — and the classifier's very first question is exactly that.
    /// Without the stamp our own mode-B exception routes (a `/32` pulled back
    /// to the primary NIC, so via the primary gateway) look precisely like a
    /// VPN's bootstrap host route: they were collected as "VPN server IPs",
    /// exempted from the block-all forever, and cached under the secondary's
    /// ifindex so they outlived the rules that created them.
    fn stamped_with_ownership(&self, mut routes: Vec<RouteEntry>) -> Vec<RouteEntry> {
        for route in &mut routes {
            if !route.is_ours && self.reconciler.owns(route) {
                route.is_ours = true;
            }
        }
        routes
    }

    fn apply_local_network_policy(
        &self,
        sid: &str,
        routes: &[RouteEntry],
        secondary_ifindex: Option<u32>,
        out: &mut Vec<(Ipv4Addr, u8)>,
    ) {
        let adapters = self.api.get_adapter_infos().unwrap_or_default();
        for subnet in crate::route_reconciler::virtual_machine_local_subnets(
            routes,
            &adapters,
            secondary_ifindex,
        ) {
            if !out.contains(&subnet) {
                out.push(subnet);
            }
        }
        let Some(policy) = self.local_networks.as_ref().map(|read| read(sid)) else {
            return;
        };
        // An answer was given about an ADAPTER, so it carries over to whatever
        // segment that adapter holds now. A refusal outranks a confirmation
        // through the retain below, which is the direction that never reopens
        // something the user closed.
        let mut allowed = policy.allowed.clone();
        let mut refused = policy.refused.clone();
        for (adapter, allow) in &policy.adapter_answers {
            for info in adapters
                .iter()
                .filter(|info| preferred_display_name(info) == adapter)
            {
                for (net, prefix) in primary_local_subnets(routes, info.index) {
                    let Some(network) = Ipv4Network::new(net, prefix) else {
                        continue;
                    };
                    if *allow {
                        allowed.push(network);
                    } else {
                        refused.push(network);
                    }
                }
            }
        }
        for network in &allowed {
            let pair = (network.network(), network.prefix_len());
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
        // Compared as NETWORKS, not as pairs: the route table and the user's
        // text can spell the same network differently.
        out.retain(|(net, prefix)| {
            Ipv4Network::new(*net, *prefix).is_none_or(|candidate| !refused.contains(&candidate))
        });
    }

    /// Tell subscribers whether this SID's policy is in force, and what to do
    /// when it is not. Published on CHANGE only: the resolve runs at reconcile
    /// cadence and an unchanged state is not news.
    /// Tell the user a tunnel is up while nothing is bound to the additional
    /// route — the setup where every rule that names the additional route
    /// silently does nothing, which reads as the product being broken.
    ///
    /// A corporate client is left alone: it usually belongs to an employer and
    /// is not a candidate for the additional route. See
    /// [`StatusUpdateEvent::UnassignedTunnelDetected`] for why the ambiguous,
    /// protocol-named clients count as personal.
    fn offer_unassigned_tunnel(
        &self,
        sid: &str,
        infos: &[nrr_platform_api::adapters::AdapterInfo],
    ) {
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        let Some(name) = personal_tunnel_name(infos) else {
            return;
        };
        let key = format!("{sid}|{name}");
        let now = std::time::Instant::now();
        {
            let mut seen = self
                .unassigned_tunnel_notified
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(last) = seen.get(&key) {
                if now.duration_since(*last) < std::time::Duration::from_secs(24 * 60 * 60) {
                    return;
                }
            }
            seen.insert(key, now);
        }
        bus.publish_for(
            sid,
            nrr_shared::ipc_payloads::StatusUpdateEvent::UnassignedTunnelDetected {
                sid: sid.to_string(),
                adapter_name: name,
            },
        );
    }

    fn publish_enforcement_status(
        &self,
        sid: &str,
        status: &str,
        role: &str,
        candidates: Vec<String>,
    ) {
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        // Keyed by role: one user can have a resolved secondary and a missing
        // primary at the same time, and a single per-SID latch made the two
        // states overwrite each other into an endless alternating push.
        let key = format!("{sid}|{role}");
        let fingerprint = format!("{status}|{}", candidates.join(","));
        {
            let mut seen = self
                .enforcement_status
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if seen.get(&key) == Some(&fingerprint) {
                return;
            }
            seen.insert(key, fingerprint);
        }
        bus.publish_for(
            sid,
            nrr_shared::ipc_payloads::StatusUpdateEvent::EnforcementStatusChanged {
                sid: sid.to_string(),
                status: status.to_string(),
                role: role.to_string(),
                candidates,
            },
        );
    }

    /// Resolve one route binding (primary or secondary) to a
    /// [`SecondaryRouteTarget`] against live `infos`. `None` when the bound
    /// adapter is missing, unusable, or has no gateway and no derivable
    /// next-hop. `role` ("primary"/"secondary") only labels the diagnostics.
    fn resolve_binding_target(
        &self,
        sid: &str,
        binding: &PerSidBinding,
        infos: &[AdapterInfo],
        role: &str,
    ) -> Option<SecondaryRouteTarget> {
        // Granular resolution so the log names the EXACT reason: not-found
        // (id mismatch), down/no-IP, or up-but-no-gateway.
        // resolve by id, but only ACCEPT the by-id match when it is
        // actually usable (Available = up + IPv4). A found-but-DOWN bound adapter
        // (a GUID-churning VPN like swiftvpn can leave a stale/down TAP instance
        // enumerated while the freshly-connected one carries traffic) must NOT short-
        // circuit to fail-closed — it falls into the same name-heal below so we can
        // adopt a live same-name SIBLING. If the bound adapter is genuinely down with
        // no live sibling, the heal finds nothing and we still fail closed (correct).
        let by_id = infos
            .iter()
            .find(|i| binding_matches_live(i, &binding.stable_id, &binding.known_stable_ids));
        let info = match by_id
            .filter(|i| classify_availability(i) == Some(AdapterAvailability::Available))
        {
            Some(i) => i,
            None => {
                // Auto-heal: the stored GUID is gone (VPN reinstall/upgrade — same
                // adapter name, new GUID) OR the bound instance is present-but-down.
                // Match by the binding's saved display_name against live adapters,
                // but ONLY when EXACTLY ONE *usable* (Available) adapter matches, so we
                // never silently route through the wrong NIC. Iterator (not a
                // Vec of borrows) so the chosen `&AdapterInfo` borrows `infos`
                // directly and outlives this block.
                let mut healed = infos.iter().filter(|i| {
                    classify_availability(i) == Some(AdapterAvailability::Available)
                        && adapter_answers_to_saved_name(i, &binding.display_name)
                });
                let first = healed.next();
                let second = healed.next();
                let ambiguous = second.is_some();
                // Several live adapters answer to the saved name: picking one
                // would route the user's traffic through an adapter they never
                // chose, so the choice goes back to them instead of being made
                // silently or swallowed into a fail-closed nobody can explain.
                if let (Some(a), Some(b)) = (first, second) {
                    let candidates: Vec<String> = std::iter::once(a)
                        .chain(std::iter::once(b))
                        .chain(healed)
                        .map(|i| preferred_display_name(i).to_string())
                        .collect();
                    self.publish_enforcement_status(sid, "adapter-choice-needed", role, candidates);
                }
                match first {
                    Some(only) if !ambiguous => {
                        let healed_id = format!(
                            "win-adapter:{}",
                            only.adapter_name.trim().to_ascii_lowercase()
                        );
                        // The heal re-fires every reconcile while the binding
                        // stays stale; act once per distinct stale→healed mapping
                        // so the WARN does not flood the log AND we persist only
                        // once (until it changes).
                        if self.note_heal_once(sid, role, &binding.stable_id, &healed_id) {
                            tracing::warn!(
                                target: "nrr::route-coordinator",
                                sid = %sid,
                                role = role,
                                stale_id = %binding.stable_id,
                                healed_adapter = %only.description,
                                healed_id = %healed_id,
                                "stored binding id was stale (adapter reinstalled/renamed?) — auto-matched the live adapter by saved name; persisting the corrected id.",
                            );
                            // persist the corrected identity so the
                            // stale id does not resurface every restart (churn)
                            // and the GUI reflects the real adapter. Safe here:
                            // the settings DB was loaded and released before this
                            // heal, so the callback may re-open it to write.
                            if let Some(persist) = self.binding_heal_persist.as_ref() {
                                persist(sid, role, &healed_id, preferred_display_name(only));
                            }
                        }
                        only
                    }
                    _ => {
                        // Heal found 0 or >1 usable same-name adapters. Fail closed,
                        // naming the EXACT reason (HW-0712 C6): a genuinely-absent
                        // bound id vs a present-but-DOWN bound adapter whose live
                        // same-name sibling we could not uniquely identify.
                        match by_id {
                            Some(down) => {
                                if self.note_not_usable_once(sid, role, &binding.stable_id) {
                                    tracing::warn!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        stable_id = %binding.stable_id,
                                        avail = ?classify_availability(down),
                                        oper_status = ?down.oper_status,
                                        has_ipv4 = down.has_ipv4_address(),
                                        name_match_ambiguous = ambiguous,
                                        "bound adapter found but NOT usable (down / no IPv4 / excluded type) and no unique live same-name adapter to heal to — failing closed",
                                    );
                                }
                                // Steady "still not usable" state is silent by
                                // design (0725 run 9: the per-reconcile debug
                                // heartbeat wrote 2500+ identical lines in ten
                                // minutes of verbose capture). The transition
                                // into the state warned above; the transition
                                // out re-arms via `clear_not_usable`.
                                //
                                // The user, however, must not be left guessing:
                                // failing closed here is what stops their rule
                                // traffic, and until this push existed the only
                                // trace was a log line. Deduped inside the
                                // publisher, so the steady state stays quiet.
                                self.publish_enforcement_status(
                                    sid,
                                    "secondary-down",
                                    role,
                                    Vec::new(),
                                );
                            }
                            None => {
                                // The user has to hear this one. The bound
                                // adapter is not among the live set and no
                                // live name answers for it — their rules stop
                                // and nothing else in the product says why.
                                // Until now this branch only wrote a log line,
                                // while its sibling (bound-but-down) published
                                // a status, so a vendor that replaced its
                                // adapter outright failed silently.
                                //
                                // Every usable adapter is offered as a
                                // candidate: we cannot know which one replaced
                                // the old one, and guessing is what the
                                // ambiguous branch above already refuses to do.
                                //
                                // Strictly the ZERO-match case. Several names
                                // answering is a different question, already
                                // asked above, and publishing both leaves the
                                // two statuses overwriting each other in the
                                // per-role latch — an endless alternating push.
                                if !ambiguous {
                                    let choices: Vec<String> = infos
                                        .iter()
                                        .filter(|i| {
                                            classify_availability(i)
                                                == Some(AdapterAvailability::Available)
                                        })
                                        .map(|i| preferred_display_name(i).to_string())
                                        .collect();
                                    // "Removed" and "here but its driver
                                    // will not start" arrive identically —
                                    // as nothing — yet they need opposite
                                    // advice: pick another connection, or
                                    // repair a driver. Only the OS can tell
                                    // them apart, and only when asked.
                                    let status = self
                                        .device_status
                                        .as_ref()
                                        .and_then(|p| p.device_state(&binding.stable_id))
                                        .filter(|s| s.is_present_but_unusable())
                                        .map_or("adapter-gone", |_| "adapter-failed");
                                    self.publish_enforcement_status(sid, status, role, choices);
                                }
                                let live: Vec<String> = infos
                                    .iter()
                                    .map(|i| {
                                        format!(
                                            "win-adapter:{}",
                                            i.adapter_name.trim().to_ascii_lowercase()
                                        )
                                    })
                                    .collect();
                                // dedup: WARN once per distinct (bound id,
                                // live adapter set); a legitimately-absent secondary
                                // (VPN off) otherwise floods the log every reconcile.
                                let mut fp_parts = live.clone();
                                fp_parts.sort();
                                let live_fp = fp_parts.join(",");
                                if self.note_not_found_once(sid, role, &binding.stable_id, &live_fp)
                                {
                                    tracing::warn!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        bound = %binding.stable_id,
                                        display_name = %binding.display_name,
                                        name_match_ambiguous = ambiguous,
                                        live_adapters = ?live,
                                        "bound adapter NOT FOUND among live adapters (id mismatch; name auto-heal found 0 or multiple matches)",
                                    );
                                } else {
                                    tracing::debug!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        bound = %binding.stable_id,
                                        "bound adapter still NOT FOUND (deduped; live adapter set unchanged)",
                                    );
                                }
                            }
                        }
                        return None;
                    }
                }
            }
        };
        // `info` is guaranteed Available here: the by-id match only accepted an
        // Available adapter, and the name-heal only adopts an Available sibling — so
        // the old post-match usability check was redundant and has been removed
        // A genuinely-down bound adapter with no live sibling already
        // returned None (fail-closed) above.
        //
        // The binding resolved to a usable adapter on this call — re-arm the
        // not-usable WARN latch so the next usable→not-usable transition logs
        // again instead of staying silently deduped forever.
        self.clear_not_usable(sid, role);
        self.publish_enforcement_status(sid, "ok", role, Vec::new());
        self.remember_mac_anchor(sid, role, binding, info);
        let gateway = match info.gateways.first().copied() {
            Some(gw) => gw,
            None => {
                // No classic adapter gateway. Common for OpenVPN / WireGuard
                // TUN links, which install split-default routes via the tunnel
                // peer instead of setting a gateway on the adapter. Derive that
                // peer from the OS route table so our routes travel exactly like
                // the link's own traffic, instead of tearing every route down
                // (the round-6 "NO gateway" dead end).
                let derived = self
                    .api
                    .get_ip_forward_table()
                    .ok()
                    .and_then(|t| derive_secondary_next_hop(&t, info.index));
                match derived {
                    Some(nh) => {
                        // Cache it so we can still route after slice-C2 strips
                        // the catch-all routes we derived it from. Refreshed on
                        // every successful derive (e.g. after a VPN reconnect).
                        // Caching it is what lets routing survive slice-C2
                        // stripping the catch-all routes we derived it from;
                        // the same write says whether this answer is news, so
                        // an unchanged next-hop stops repeating itself into the
                        // log every cycle.
                        if self.note_derived_next_hop(info.index, nh) {
                            tracing::debug!(
                                target: "nrr::route-coordinator",
                                sid = %sid,
                                role = role,
                                ifindex = info.index,
                                next_hop = %nh,
                                "bound adapter exposes no gateway; derived tunnel next-hop from its catch-all routes",
                            );
                        }
                        nh
                    }
                    None => {
                        // Derivation failed — typically because NetRuleRouter
                        // already owns the table and stripped the VPN's redirect
                        // overlay (the only catch-all we could derive from). Fall
                        // back to the last good next-hop for this interface.
                        let cached = self
                            .next_hop_cache
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .get(&info.index)
                            .copied();
                        match cached {
                            Some(nh) => {
                                tracing::debug!(
                                    target: "nrr::route-coordinator",
                                    sid = %sid,
                                    role = role,
                                    ifindex = info.index,
                                    next_hop = %nh,
                                    "no catch-all on interface (NetRuleRouter owns the table now) — using cached tunnel next-hop",
                                );
                                nh
                            }
                            None => {
                                // Log BOTH the stored (possibly stale) binding
                                // id AND the effective adapter we actually
                                // resolved to (healed-by-name id + ifindex), so
                                // the operator can see it operated on the LIVE
                                // adapter, not the stale GUID. The old log
                                // printed only `binding.stable_id` while working
                                // on `info.index`, which read like an adapter
                                // mismatch  HW diagnosis).
                                let effective_id = format!(
                                    "win-adapter:{}",
                                    info.adapter_name.trim().to_ascii_lowercase()
                                );
                                // Once per spell  HW: this state is
                                // a short burst while the VPN client is still
                                // installing its routes after media-up, and
                                // resolution runs many times per second — 55
                                // identical WARNs in 2.2 s without the latch).
                                if self.note_no_next_hop_once(sid, role) {
                                    tracing::warn!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        stable_id = %binding.stable_id,
                                        effective_id = %effective_id,
                                        effective_adapter = %info.description,
                                        ifindex = info.index,
                                        ipv4 = ?info.ipv4_addresses,
                                        "bound adapter is UP but has NO gateway and no derivable or cached tunnel next-hop (only on-link routes) — cannot use it as a route target",
                                    );
                                } else {
                                    tracing::debug!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        ifindex = info.index,
                                        "still no derivable or cached tunnel next-hop (deduped)",
                                    );
                                }
                                return None;
                            }
                        }
                    }
                }
            }
        };
        // The binding resolved to a full route target — re-arm the
        // no-next-hop WARN latch for the next derivation outage.
        self.clear_no_next_hop(sid, role);
        Some(SecondaryRouteTarget {
            gateway,
            interface_index: info.index,
        })
    }

    /// active-probe liveness gate on the SECONDARY only
    /// (never the primary — the real link must never be probed / fail-closed).
    /// If the tunnel next-hop has been UNREACHABLE for the whole configured
    /// window, treat the secondary as unresolved so routes tear down and the
    /// kill-switch fail-closes — even though the adapter still enumerates
    /// Up+IPv4 (the dead-but-Up case route-table inspection can't catch, since
    /// NetRuleRouter owns/mutates the table). Disabled (window 0) → `is_dead` is
    /// always false → returns the raw target unchanged (no behaviour change).
    fn gate_secondary_on_liveness(
        &self,
        sid: &str,
        raw: Option<SecondaryRouteTarget>,
    ) -> Option<SecondaryRouteTarget> {
        match raw {
            Some(t) if self.liveness.is_dead(t.interface_index, Instant::now()) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    ifindex = t.interface_index,
                    next_hop = %t.gateway,
                    window_secs = self.liveness.window_secs(),
                    "secondary tunnel next-hop UNREACHABLE for the whole liveness window — treating the secondary as DEAD (kill-switch fail-closed), even though the adapter is still Up+IPv4",
                );
                None
            }
            other => other,
        }
    }

    /// probe each active user's bound secondary tunnel
    /// next-hop and feed the reachability result to the liveness tracker. Driven
    /// by the `secondary-liveness-tick` at a fast cadence while a secondary is
    /// bound. No-op when the feature is disabled (window 0) or no probe is wired.
    /// Uses the RAW resolution (NOT the liveness gate) so a currently-dead tunnel
    /// is still probed and can RECOVER once it answers again.
    pub fn probe_active_secondaries(&self, sids: &[String]) {
        if !self.liveness.enabled() {
            return;
        }
        let Some(probe) = self.reachability_probe.as_ref() else {
            return;
        };
        let infos = match self.api.get_adapter_infos() {
            Ok(i) => i,
            Err(_) => return,
        };
        for sid in sids {
            let Some(policy) = self.route_source.load_for_sid(sid) else {
                continue;
            };
            let Some(binding) = policy.secondary.as_ref() else {
                continue;
            };
            match self.resolve_binding_target(sid, binding, &infos, "secondary") {
                Some(t) => {
                    // A tunnel adapter that is recreated comes back under a NEW
                    // ifindex, and the liveness window is keyed by index. Left
                    // alone, the old index keeps whatever it had accumulated
                    // (nobody probes it again to clear it), and — worse — the
                    // new index may be one an unrelated adapter already filled
                    // with failures, which would declare a healthy tunnel dead
                    // on its first probe. Same reasoning as the `None` arm
                    // below: a different interface must re-prove its baseline.
                    let replaced = self
                        .probed_ifindex
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(sid.clone(), t.interface_index);
                    if let Some(old) = replaced.filter(|old| *old != t.interface_index) {
                        self.liveness.forget(old);
                        self.liveness.forget(t.interface_index);
                    }
                    // A peerless tunnel (on-link forwarding) has no next-hop to
                    // echo; an echo to 0.0.0.0 would fail every time and declare
                    // a working link dead. Nothing is recorded, so the window
                    // stays empty and the gate stays open.
                    if t.gateway.is_unspecified() {
                        continue;
                    }
                    let reachable = probe.is_reachable(t.gateway, LIVENESS_PROBE_TIMEOUT);
                    self.liveness
                        .record(t.interface_index, reachable, Instant::now());
                }
                None => {
                    // The bound secondary is unprobeable right now (adapter
                    // down / no IPv4 / no next-hop — a VPN mid-reconnect).
                    // Whatever failing run was accumulating no longer measures
                    // this tunnel: drop it, or the stale window declares the
                    // adapter DEAD the instant it comes back Up and the
                    // kill-switch fail-closes a freshly-reconnected tunnel
                    //  HW). The interface must re-prove its
                    // reachability baseline after it returns.
                    let forgotten = self
                        .probed_ifindex
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(sid);
                    if let Some(old) = forgotten {
                        self.liveness.forget(old);
                    }
                }
            }
        }
    }

    /// Recompute and apply the system route table from `sid`'s effective rule
    /// book and resolved routing inputs (own revision, or baseline via the
    /// provider's read-through).
    ///
    /// `resolution.secondary == None` means the user has no usable secondary
    /// right now — every owned route is torn down so traffic falls back to the
    /// OS default routing (fail-closed blocking, when configured, is the WFP
    /// layer's job, not ours). The behavior mode decides the shape: mode A
    /// pulls secondary-bound rules into the tunnel as `/32`; mode B owns a
    /// split-default overlay via the secondary and carves primary-bound rules
    /// back onto the primary NIC (block 16.18.vpn).
    pub fn recompute_for(
        &self,
        sid: &str,
        resolution: &RouteResolution,
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let Some(secondary) = resolution.secondary else {
            // resolve() already logged the specific reason. The tunnel is gone,
            // so its interior is nobody's subnet any more — publish the empty
            // set rather than leave a stale one gating fake-IP answers.
            crate::secondary_subnets::global_secondary_subnets().publish(Vec::new());
            return self.reconciler.clear();
        };
        // The tunnel's own interior, refreshed while we already hold the
        // enumeration: the fake-IP answerer must never substitute an address
        // inside it (a VPN client authorizing against its own tunnel address is
        // the live case).
        self.publish_secondary_subnets(sid);
        let Some(snapshot) = self.rules_provider.active_rules_for(sid) else {
            // No effective rules for this principal → no routes.
            tracing::info!(
                target: "nrr::route-coordinator",
                sid = %sid,
                "no active rules for this user — no secondary routes",
            );
            return self.reconciler.clear();
        };
        // shared-IP denylist from the same enforcement rule
        // book + live cache, keyed on this SID's policy, so the route table and
        // the WFP set decline the same shared IPs.
        let stored_policy = self.route_source.load_for_sid(sid);
        let shared_ip_policy = stored_policy
            .as_ref()
            .map(|p| p.shared_ip_policy)
            .unwrap_or_default();
        // Zone-vs-exact-address order comes from the same stored policy: the
        // routes and the filters must arbitrate one address identically.
        let zone_order = crate::address_ownership::ZoneVsIpOrder::from_zone_priority_over_ip(
            stored_policy
                .as_ref()
                .is_some_and(|p| p.zone_priority_over_ip),
        );
        let denied = crate::secondary_ip_policy::secondary_ip_denylist(
            &snapshot.rule_book.secondary,
            self.fqdn_cache.as_ref(),
            shared_ip_policy,
        );
        // The tunnel's own redirect prefixes shape mode A's counter-overlay.
        // Read here, not cached: a client that reconnects may lay them out
        // differently, and the reconcile that follows must answer that layout.
        let tunnel_catch_alls = self
            .api
            .get_ip_forward_table()
            .map(|t| {
                let t = self.stamped_with_ownership(t);
                crate::route_codegen::tunnel_catch_all_prefixes(&t, secondary.interface_index)
            })
            .unwrap_or_default();
        let mut out = generate_routes(
            resolution.mode,
            &snapshot.rule_book,
            resolution.primary.as_ref(),
            &secondary,
            self.fqdn_cache.as_ref(),
            self.app_observations.as_ref(),
            &denied,
            zone_order,
            &tunnel_catch_alls,
        );
        // DNS-over-secondary — the route half of the setting. Emitted here, not
        // in `generate_routes`, because it is not derived from the rule book:
        // it is service-owned infrastructure that must ride the same reconcile
        // (and the same teardown) as everything else we install.
        if self
            .dns_via_secondary
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
        {
            // Fast liveness check , acceptance run 9): the dead
            // verdict above has a whole hysteresis window of lag, and for that
            // window these `/32`s would blackhole every direct dial to the
            // public resolvers system-wide — including a VPN client's own
            // bootstrap DNS, which is exactly what has to work for the tunnel
            // to come back. One failed probe pulls the resolver routes; one
            // successful probe restores them on the next recompute.
            if self.liveness.in_failing_run(secondary.interface_index) {
                tracing::debug!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    secondary_ifindex = secondary.interface_index,
                    "DNS-over-secondary: last tunnel probe failed — leaving the public resolvers on the primary path until the tunnel answers again",
                );
            } else {
                let dns_routes = crate::route_codegen::dns_via_secondary_routes(
                    crate::dns_egress::PUBLIC_DNS_SERVERS,
                    &secondary,
                );
                tracing::debug!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    routes = dns_routes.len(),
                    secondary_ifindex = secondary.interface_index,
                    "DNS-over-secondary: routing the service's upstream resolvers through the tunnel",
                );
                out.routes.extend(dns_routes);
            }
        }
        if !out.diagnostics.is_empty() {
            // Counted by kind, not summed: the old line named all three possible
            // causes in its text and printed only a total, so a run where the
            // primary was missing read exactly like one with a cold DNS cache.
            let tally = diagnostic_tally(&out.diagnostics);
            tracing::debug!(
                target: "nrr::route-coordinator",
                sid = %sid,
                diagnostics = out.diagnostics.len(),
                routes = out.routes.len(),
                hostname_unresolved = tally.hostname_unresolved,
                suffix_empty = tally.suffix_empty,
                zone_empty = tally.zone_empty,
                app_rule_address_and_app_not_routed = tally.app_rule_address_and_app_not_routed,
                app_rule_unobserved = tally.app_rule_unobserved,
                app_rule_dest_claimed_by_main_link = tally.app_rule_dest_claimed_by_main_link,
                app_rule_dest_used_by_other_process = tally.app_rule_dest_used_by_other_process,
                address_claimed_by_main_link = tally.address_claimed_by_main_link,
                primary_exceptions_unavailable = tally.primary_exceptions_unavailable,
                "route codegen produced diagnostics",
            );
        }
        // Route-shape breakdown so the log alone answers "is mode-A selectivity
        // actually in place?" without Get-NetRoute: the `/2` counter-overlay
        // (unmatched → primary) only exists when a primary target resolved; a
        // `counter_overlay=0` + `primary=false` in PreferPrimary is the
        // smoking gun for "unmatched traffic is still riding the secondary".
        let counter_overlay = out.routes.iter().filter(|r| r.prefix_length == 2).count();
        let secondary_routes = out
            .routes
            .iter()
            .filter(|r| r.prefix_length == 32 && r.interface_index == secondary.interface_index)
            .count();
        let primary_present = resolution.primary.is_some();
        let delta = self.reconciler.reconcile(&out.routes)?;
        // ADD-ONLY, settled on hardware: we never remove the VPN's own
        // routes. Stripping its redirect `/1` pair made the client treat the
        // removal as a fault and reconnect, and in mode A it dropped
        // not-yet-resolved hosts (DoH-only names with no `/32`) to the primary
        // with the real IP. Mode-A selectivity rides a `/2` counter-overlay via
        // the primary instead — more specific than the VPN's `/1`, nothing
        // removed.
        if delta.is_noop() {
            // Steady state (no change this cycle) — debug, to keep the log
            // quiet once routing has converged.
            tracing::debug!(
                target: "nrr::route-coordinator",
                sid = %sid,
                secondary_ifindex = secondary.interface_index,
                desired_routes = out.routes.len(),
                "route table reconciled (no change)",
            );
        } else {
            tracing::info!(
                target: "nrr::route-coordinator",
                sid = %sid,
                mode = ?resolution.mode,
                primary = primary_present,
                secondary_ifindex = secondary.interface_index,
                desired_routes = out.routes.len(),
                secondary_routes,
                counter_overlay,
                added = delta.added,
                removed = delta.removed,
                "route table reconciled",
            );
        }
        // Counter-overlay liveness audit (mode A): re-read the live table and
        // report EVERY `/2` route, so the log alone shows whether mode-A
        // selectivity is actually in force — our `/2` must sit on the PRIMARY
        // interface to out-specific the VPN's `/1`. A `/2` on the VPN ifindex
        // (or none at all) is the smoking gun for "unmatched still rides the
        // tunnel". Only on a real change, to avoid per-cycle cost.
        if !delta.is_noop() && matches!(resolution.mode, RouteBehaviorMode::PreferPrimary) {
            if let Ok(live) = self.api.get_ip_forward_table() {
                let mut any = false;
                for r in live.iter().filter(|r| r.prefix_length == 2) {
                    any = true;
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        sid = %sid,
                        destination = %r.destination,
                        ifindex = r.interface_index,
                        next_hop = %r.next_hop,
                        metric = r.metric,
                        on_secondary = (r.interface_index == secondary.interface_index),
                        "live /2 counter-overlay route",
                    );
                }
                if !any {
                    tracing::warn!(
                        target: "nrr::route-coordinator",
                        sid = %sid,
                        "no /2 counter-overlay routes in the live table — mode-A selectivity is NOT in force; unmatched traffic will ride the VPN's redirect",
                    );
                }
            }
        }
        Ok(delta)
    }

    /// Tear down every owned route — no active user, or service stopping.
    pub fn clear(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconciler.clear()
    }

    /// Seed the reconciler's owned set for startup orphan adoption (routes
    /// already in the OS table from a previous run). The next
    /// `recompute_for` deletes the ones the active user no longer wants.
    pub fn adopt_owned(&self, routes: Vec<RouteEntry>) {
        self.reconciler.adopt_owned(routes);
    }

    /// startup orphan cleanup. A crash or hard kill (NOT a
    /// graceful stop — that path runs the teardown hook) can leave our routes
    /// in the OS table with no in-memory owner. Enumerate the live table, adopt
    /// every route matching our signature, and stamp them owned so the first
    /// `recompute_active` reconciles them — keeping the ones the active user
    /// still wants and deleting the rest.
    ///
    /// Two route shapes carry our signature, both at the uncommon
    /// [`SECONDARY_ROUTE_METRIC`]: the `/32` secondary host routes (on the
    /// secondary NIC) AND the mode-A `/2` counter-overlay halves ([`COUNTER_OVERLAY`], on
    /// the primary NIC). We adopt BOTH. Originally only `/32` was adopted,
    /// so a `/2` overlay orphaned by a crash was stranded in
    /// the OS table indefinitely — it could send all non-rule traffic to the
    /// primary even after the service that wanted it was gone, the kind of
    /// leftover that broke connectivity after a kill-during-rebuild.)
    ///
    /// The signature is a heuristic (the OS never tags routes as ours); a
    /// third-party route at the same metric would be adopted and then deleted
    /// if not re-desired. The metric is deliberately uncommon to make that
    /// vanishingly unlikely. Enumeration failure is non-fatal: we log and adopt
    /// nothing (the next reconcile still installs the desired set; a stale
    /// route would linger until then).
    pub fn adopt_orphans_from_table(&self) {
        let table = match self.api.get_ip_forward_table() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    "route table enumeration failed during startup orphan adoption: {e:?}",
                );
                return;
            }
        };
        let orphans: Vec<RouteEntry> = table
            .into_iter()
            .filter(|r| {
                // Shape asked of the codegen, never restated here: a mode that
                // grows a shape this list does not know leaves those routes
                // unadopted after a crash, pointing traffic at a dead tunnel
                // with nothing left to reclaim them.
                r.metric == crate::route_codegen::SECONDARY_ROUTE_METRIC
                    && crate::route_codegen::is_owned_prefix_length(r.prefix_length)
            })
            .map(|mut r| {
                r.is_ours = true;
                r
            })
            .collect();
        if !orphans.is_empty() {
            tracing::info!(
                target: "nrr::route-coordinator",
                count = orphans.len(),
                "adopted orphaned secondary routes from a previous run",
            );
        }
        self.reconciler.adopt_owned(orphans);
    }

    /// Number of routes currently owned (for diagnostics/tests).
    pub fn owned_count(&self) -> usize {
        self.reconciler.owned_count()
    }
}

/// wraps the WFP per-SID apply trigger so a policy
/// change also recomputes the **route table** for the active user.
///
/// `RoutePolicyUpdate` (binding change) and rules mutations both fire
/// `on_policy_changed(sid)`. The inner trigger recompiles that SID's WFP
/// filters (already M-1-gated on tray presence). This wrapper additionally
/// recomputes the route table **only when the changed SID is the active
/// routing user** — routes follow the single active console user, so a
/// background user's edit must not rewrite the machine-wide table.
pub struct RouteAndFilterApplyTrigger {
    inner: Arc<dyn crate::ipc_handlers::providers::RoutePolicyApplyTrigger>,
    route_coord: Arc<SecondaryRouteCoordinator>,
    registry: Arc<crate::active_sid_registry::ActiveSidRegistry>,
}

impl RouteAndFilterApplyTrigger {
    pub fn new(
        inner: Arc<dyn crate::ipc_handlers::providers::RoutePolicyApplyTrigger>,
        route_coord: Arc<SecondaryRouteCoordinator>,
        registry: Arc<crate::active_sid_registry::ActiveSidRegistry>,
    ) -> Self {
        Self {
            inner,
            route_coord,
            registry,
        }
    }
}

impl crate::ipc_handlers::providers::RoutePolicyApplyTrigger for RouteAndFilterApplyTrigger {
    fn on_policy_changed(&self, sid: &str) {
        // 1. WFP filters (per-SID, M-1-gated inside the inner trigger).
        self.inner.on_policy_changed(sid);
        // 2. Route table — re-drive when the changed policy affects the user we
        //    actually enforce for. With a tray that's a connected SID; under
        //    service-driven scope with NO tray it is the active console user, so
        //    a change to THEIR rules — or to the shared baseline they inherit —
        //    must re-drive even though the registry is empty (block 16,
        //    ; previously this required the SID to be in the registry,
        //    so service-driven-from-boot policy edits were ignored until a tray
        //    connected or the periodic safety recompute caught up).
        let active = self.registry.active_sids();
        let relevant = match self.route_coord.effective_routing_sid(&active).as_deref() {
            Some(eff) => {
                eff == sid
                    // The shared baseline is read THROUGH by every user who has
                    // not diverged from it, so editing it changes what we
                    // enforce for whoever we enforce for — with a tray
                    // connected exactly as much as without one. Gating this on
                    // an empty registry meant an admin's baseline edit reached
                    // the filters and stopped at the route table for as long as
                    // a tray was up. Deciding here whether the effective
                    // principal still inherits would mean re-deriving their
                    // revision; the recompute is a diff and costs one no-op
                    // pass when they do not.
                    || sid == nrr_domain::user_principal::BASELINE_PRINCIPAL
            }
            None => false,
        };
        if relevant {
            match self.route_coord.recompute_active(&active) {
                Ok(delta) if !delta.is_noop() => tracing::info!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    added = delta.added,
                    removed = delta.removed,
                    "route table recomputed after policy change",
                ),
                Ok(_) => {}
                Err(e) => tracing::error!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "route recompute after policy change failed: {e:?}",
                ),
            }
        }
    }
}

/// The connection name of an up personal-VPN tunnel, if one is present.
///
/// Both names are tested: a VPN client commonly keeps the stock driver
/// description ("TAP-Windows Adapter V9") and renames only the connection, so
/// reading either one alone misses half the installations.
fn personal_tunnel_name(infos: &[nrr_platform_api::adapters::AdapterInfo]) -> Option<String> {
    use nrr_platform_api::vpn_discovery::{vpn_client_class, VpnClientClass};
    infos
        .iter()
        .find(|info| {
            info.oper_status == nrr_platform_api::adapters::IfOperStatus::Up
                && [info.friendly_name.as_str(), info.description.as_str()]
                    .iter()
                    .any(|name| vpn_client_class(name) == Some(VpnClientClass::Consumer))
        })
        .map(|info| {
            if info.friendly_name.is_empty() {
                info.description.clone()
            } else {
                info.friendly_name.clone()
            }
        })
}

#[cfg(test)]
mod tests;

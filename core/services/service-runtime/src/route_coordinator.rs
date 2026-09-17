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
    derive_secondary_next_hop, derive_secondary_next_hop_v6, diagnostic_tally, mac_anchor_id,
    preferred_display_name, replacement_candidates,
};
pub use binding_resolver::{adapter_binding_matches, adapter_entry_binding_matches};
// Read only by this module's tests, which sit in a sibling file and reach it
// through `super::`.
#[cfg(test)]
use binding_resolver::description_matches_display_name;

/// Resolved routing inputs for one principal: the active behavior mode plus
/// the usable primary/secondary targets. `secondary ==
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
/// 30 s safety tick does not clobber a `Persist` opt-in. On pause the route
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
    /// The resolution each principal's last full recompute used. A first
    /// contact plans from it instead of re-reading the adapters on the DNS path.
    last_resolution: Mutex<HashMap<String, RouteResolution>>,
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

mod apply;
mod liveness;
mod networks;
mod recompute;
mod resolve;
mod wiring;

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
        //    must re-drive even though the registry is empty, or
        //    service-driven-from-boot policy edits go unenforced until a tray
        //    connects or the periodic safety recompute catches up.
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

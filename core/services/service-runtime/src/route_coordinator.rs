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

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nrr_domain::RouteBehaviorMode;
use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::reachability::ReachabilityProbe;
use nrr_platform_api::{
    classify_availability, AdapterAvailability, PlatformError, RouteEntry, WindowsApiPort,
};

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

/// Resolve the [`SecondaryRouteTarget`] (gateway + interface index) for a
/// principal from its per-SID secondary binding and live adapter info.
///
/// Returns `None` when the principal has no secondary bound, the bound
/// adapter is not present / has no usable IPv4 + gateway, i.e. there is
/// nowhere to route. The coordinator treats `None` as "tear down routes".
pub fn resolve_secondary_target(
    secondary_stable_id: &str,
    adapter_infos: &[AdapterInfo],
) -> Option<SecondaryRouteTarget> {
    let info = adapter_infos
        .iter()
        .find(|i| adapter_binding_matches(i, secondary_stable_id))?;
    // Only route when the adapter is actually usable (up + has IPv4).
    if classify_availability(info) != Some(AdapterAvailability::Available) {
        return None;
    }
    let gateway = info.gateways.first().copied()?;
    Some(SecondaryRouteTarget {
        gateway,
        interface_index: info.index,
    })
}

/// Match a stored route-binding id against a live [`AdapterInfo`].
///
/// The binding stores the GUI **snapshot persistent id**
/// (`win-adapter:{lowercased-adapter-name}`, or the
/// `win-ifindex-mac:{idx}:{MAC}` / `win-ifindex:{idx}` fallbacks) produced by
/// `nrr_platform_api::interface_manager::build_persistent_id`. The
/// low-level `AdapterInfo::stable_id()` uses a DIFFERENT scheme (MAC hex, or
/// the bare adapter name) — so a direct `stable_id()` compare NEVER matched a
/// real binding. That silent mismatch made the coordinator report
/// "secondary adapter not found" for a live, working VPN and route nothing.
/// Reconstruct the persistent id here (keep in sync with `build_persistent_id`).
pub fn adapter_binding_matches(info: &AdapterInfo, bound_id: &str) -> bool {
    let mac_dash = info.mac.map(|mac| {
        mac.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join("-")
    });
    identity_matches(
        &info.adapter_name,
        info.index,
        mac_dash.as_deref(),
        &info.stable_id(),
        bound_id,
    )
}

/// Same matching rules as [`adapter_binding_matches`], for the wire-shaped
/// [`AdapterEntry`] the IPC layer hands to per-SID consumers (e.g. the
/// Fail-Closed probe) that only ever see the already-enumerated snapshot,
/// not the raw platform-api `AdapterInfo` list.
///
/// `AdapterEntry::physical_address` is colon-separated hex (see
/// `adapter_to_entry`); normalize to the dash form the persistent-id scheme
/// uses before comparing. `AdapterEntry::persistent_id` is populated from
/// `AdapterInfo::stable_id()`, so it is the correct back-compat fallback.
pub fn adapter_entry_binding_matches(
    entry: &nrr_shared::ipc_payloads::AdapterEntry,
    bound_id: &str,
) -> bool {
    let mac_dash = entry
        .physical_address
        .as_deref()
        .map(|mac| mac.replace(':', "-"));
    identity_matches(
        &entry.adapter_name,
        entry.ipv6_if_index,
        mac_dash.as_deref(),
        &entry.persistent_id,
        bound_id,
    )
}

/// Core identity-matching rules, parametrized over the fields both adapter
/// representations in this crate carry. `stable_id_fallback` is the
/// low-level `AdapterInfo::stable_id()` value, kept for bindings persisted
/// before the `win-adapter:`/`win-ifindex-mac:`/`win-ifindex:` scheme
/// existed.
fn identity_matches(
    name: &str,
    index: u32,
    mac_dash: Option<&str>,
    stable_id_fallback: &str,
    bound_id: &str,
) -> bool {
    let name = name.trim().to_ascii_lowercase();
    if !name.is_empty() && bound_id.eq_ignore_ascii_case(&format!("win-adapter:{name}")) {
        return true;
    }
    if let Some(mac) = mac_dash {
        if bound_id.eq_ignore_ascii_case(&format!("win-ifindex-mac:{index}:{mac}")) {
            return true;
        }
    }
    if bound_id.eq_ignore_ascii_case(&format!("win-ifindex:{index}")) {
        return true;
    }
    // Back-compat: a binding stored with the low-level stable_id scheme.
    bound_id.eq_ignore_ascii_case(stable_id_fallback)
}

/// match a live adapter against a binding's current
/// `stable_id` OR any previously-known id the auto-heal folded in. A VPN whose
/// GUID rotated across a reinstall is recognised directly by a prior id,
/// without depending on the friendly-name heal firing again this session.
fn binding_matches_live(info: &AdapterInfo, stable_id: &str, known_ids: &[String]) -> bool {
    adapter_binding_matches(info, stable_id)
        || known_ids.iter().any(|id| adapter_binding_matches(info, id))
}

/// `true` when a whitespace token of an adapter friendly name is purely a
/// version designator (all digits/dots, optionally a leading `v`): "3.0",
/// "4.1", "v3", "2". VPN vendors bump these across reinstalls/upgrades
/// ("hidemy.name VPN OpenVPN Adapter" ↔ "hidemy.name VPN 3.0 OpenVPN
/// Adapter"), so a version token must never participate in identity matching.
fn is_version_token(token: &str) -> bool {
    let stripped = token.trim_start_matches(['v', 'V']);
    !stripped.is_empty() && stripped.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Lower-cased whitespace tokens of a friendly name with version tokens
/// dropped — the stable "family" identity of an adapter description.
fn core_tokens(name: &str) -> Vec<String> {
    name.split_whitespace()
        .filter(|t| !is_version_token(t))
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

/// Heuristic name-family match for the stale-GUID auto-heal: `true` when the
/// binding's saved `display_name` and the live adapter's `description` name
/// the SAME adapter family, ignoring version tokens.
///
/// Both sides are reduced to their version-stripped core token set (so
/// "hidemy.name VPN OpenVPN Adapter" and "hidemy.name VPN 3.0 OpenVPN Adapter"
/// reduce to the same family), then matched by **symmetric** containment:
/// either core set is a subset of the other. The earlier implementation
/// required the saved name to be a subset of the live description — a
/// directional test that silently failed the "every other day" case (HW-0708)
/// where the SAVED name carried the version token and the live adapter dropped
/// it (saved "…VPN 3.0 OpenVPN Adapter" vs live "…VPN OpenVPN Adapter"),
/// leaving a live, working VPN reported as "not found among live adapters".
/// Symmetric containment heals both directions. The caller only uses this when
/// EXACTLY ONE usable adapter matches, bounding false positives.
fn description_matches_display_name(description: &str, display_name: &str) -> bool {
    let saved = core_tokens(display_name);
    let live = core_tokens(description);
    if saved.is_empty() || live.is_empty() {
        return false;
    }
    saved.iter().all(|t| live.contains(t)) || live.iter().all(|t| saved.contains(t))
}

/// Does `info` still answer to the name the binding was saved under?
///
/// The saved name is whatever the GUI showed, which is the CONNECTION name
/// (`friendly_name`) — a VPN client that renames its connection but ships the
/// stock driver ("TAP-Windows Adapter V9") shares no token with the driver
/// description, so matching the description alone leaves the heal dead exactly
/// where GUID churn makes it necessary.
fn adapter_answers_to_saved_name(info: &AdapterInfo, display_name: &str) -> bool {
    description_matches_display_name(&info.description, display_name)
        || description_matches_display_name(&info.friendly_name, display_name)
}

/// The name to store for an adapter: the connection name the GUI lists, with
/// the driver description as the fallback.
fn preferred_display_name(info: &AdapterInfo) -> &str {
    let friendly = info.friendly_name.trim();
    if friendly.is_empty() {
        &info.description
    } else {
        friendly
    }
}

/// Derive a usable next-hop for a secondary adapter that exposes **no**
/// classic default gateway. OpenVPN / WireGuard TUN links commonly install
/// split-default routes (`0.0.0.0/1` + `128.0.0.0/1`, or a plain
/// `0.0.0.0/0`) pointing at the tunnel **peer** instead of setting a
/// gateway on the adapter — so `GetAdaptersAddresses` reports an empty
/// gateway list and the adapter-gateway lookup finds nothing, even though
/// the link is up and routing fine. We reuse that peer as the next-hop for
/// our `/32` overlays so matched traffic travels exactly like the VPN's own
/// redirected traffic. (Observed on a live hidemy.name OpenVPN link:
/// `0.0.0.0/1 -> 10.91.192.1` with no adapter gateway.)
///
/// Default-style routes on `ifindex` with a real (non-unspecified,
/// non-loopback) next-hop are preferred (`/0`, then the `/1` halves, then
/// lowest metric); ANY other gateway-style route on the interface is a
/// last resort — on a point-to-point tunnel every such route
/// names the one peer, which recovers the next-hop after the catch-alls
/// were stripped and a restart lost the in-memory cache. Returns `None`
/// when the interface carries only on-link routes (host-only virtual
/// adapter, or a tunnel whose client has not yet installed any route).
/// The single implementation lives in `nrr-platform-api` so the interface
/// enumeration reports exactly the next-hop this layer would route through —
/// otherwise the GUI could call an adapter unusable that the router uses
/// happily (or the reverse).
fn derive_secondary_next_hop(routes: &[RouteEntry], ifindex: u32) -> Option<Ipv4Addr> {
    nrr_platform_api::interface_rows::derive_forwarding_next_hop(routes, ifindex)
}

/// Derive the **primary** routing target (gateway + interface) from the OS
/// default route, for when the user bound only a secondary (VPN) adapter.
///
/// Mode-A's `/2` counter-overlay (so unmatched traffic egresses the real link
/// instead of the tunnel) and mode-B's exception `/32`s both route via the
/// primary gateway. Requiring the user to *also* bind a primary just for this
/// is a footgun — "direct" silently kept unmatched traffic on the secondary
/// adapter. So when no primary is explicitly bound we fall back to the real
/// internet gateway: the lowest-metric `0.0.0.0/0` whose interface is NOT the
/// secondary and whose next-hop is a real address (the OS default-route
/// anchor the secondary adapter leaves on the physical NIC). Returns `None`
/// when no such default route exists (e.g. a
/// VPN that replaced `/0` itself) — the caller then logs the actionable gap.
fn derive_primary_target(
    routes: &[RouteEntry],
    secondary_ifindex: u32,
) -> Option<SecondaryRouteTarget> {
    let mut best: Option<(u32, Ipv4Addr, u32)> = None; // (metric, gateway, ifindex)
    for r in routes {
        if r.interface_index == secondary_ifindex {
            continue;
        }
        if !(r.destination.is_unspecified() && r.prefix_length == 0) {
            continue;
        }
        let nh = r.next_hop;
        if nh.is_unspecified() || nh.is_loopback() {
            continue;
        }
        let cand = (r.metric, nh, r.interface_index);
        best = Some(match best {
            Some(b) if b.0 <= cand.0 => b,
            _ => cand,
        });
    }
    best.map(|(_, gateway, interface_index)| SecondaryRouteTarget {
        gateway,
        interface_index,
    })
}

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
    api: Arc<dyn WindowsApiPort>,
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
        api: Arc<dyn WindowsApiPort>,
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
            heal_logged: Mutex::new(HashMap::new()),
            not_found_logged: Mutex::new(HashMap::new()),
            not_usable_logged: Mutex::new(HashMap::new()),
            no_next_hop_logged: Mutex::new(std::collections::HashSet::new()),
            probed_ifindex: Mutex::new(HashMap::new()),
            rule_scope_service_driven,
            binding_heal_persist: None,
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

    /// Returns `true` the first time a given `stale → healed` binding mapping
    /// is observed for `(sid, role)` (and again whenever it changes), `false`
    /// while it repeats. Backs the once-per-state-change dedup of the
    /// stale-binding auto-heal WARN so a long-lived stale binding does not
    /// flood the operational log every reconcile cycle.
    fn note_heal_once(&self, sid: &str, role: &str, stale_id: &str, healed_id: &str) -> bool {
        let key = format!("{sid}|{role}");
        let value = (stale_id.to_string(), healed_id.to_string());
        let mut guard = self.heal_logged.lock().unwrap_or_else(|p| p.into_inner());
        if guard.get(&key) == Some(&value) {
            return false;
        }
        guard.insert(key, value);
        true
    }

    /// Returns `true` the first time the "bound adapter NOT FOUND" state is seen
    /// for `(sid, role)` with a given `(stale_id, live-set fingerprint)`, and
    /// again whenever either changes; `false` while it repeats. Dedups the
    /// NOT-FOUND WARN so a bound-but-absent secondary (VPN turned off) does not
    /// flood the operational log at reconcile cadence.
    fn note_not_found_once(&self, sid: &str, role: &str, stale_id: &str, live_fp: &str) -> bool {
        let key = format!("{sid}|{role}");
        let value = (stale_id.to_string(), live_fp.to_string());
        let mut guard = self
            .not_found_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if guard.get(&key) == Some(&value) {
            return false;
        }
        guard.insert(key, value);
        true
    }

    /// Returns `true` the first time the "bound adapter NOT usable" state is
    /// observed for `(sid, role)` with this `stable_id`, and again whenever
    /// the adapter transitions back to not-usable after having been usable
    /// (see [`Self::clear_not_usable`]); `false` while the same not-usable
    /// spell continues. Dedups the NOT-usable WARN so a flapping adapter does
    /// not flood the operational log at reconcile cadence.
    fn note_not_usable_once(&self, sid: &str, role: &str, stable_id: &str) -> bool {
        let key = format!("{sid}|{role}");
        let mut guard = self
            .not_usable_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if guard.get(&key).map(String::as_str) == Some(stable_id) {
            return false;
        }
        guard.insert(key, stable_id.to_string());
        true
    }

    /// Re-arm [`Self::note_not_usable_once`] for `(sid, role)` — called once
    /// the binding resolves to a usable adapter again, so the next
    /// usable→not-usable transition warns instead of staying silent forever.
    fn clear_not_usable(&self, sid: &str, role: &str) {
        let key = format!("{sid}|{role}");
        let mut guard = self
            .not_usable_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.remove(&key);
    }

    /// `true` exactly once per no-next-hop spell for `(sid, role)` (see
    /// [`Self::no_next_hop_logged`]); `false` while the same spell continues.
    fn note_no_next_hop_once(&self, sid: &str, role: &str) -> bool {
        let mut guard = self
            .no_next_hop_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.insert(format!("{sid}|{role}"))
    }

    /// Re-arm [`Self::note_no_next_hop_once`] for `(sid, role)` — called once
    /// the binding resolves to a route target again.
    fn clear_no_next_hop(&self, sid: &str, role: &str) {
        let mut guard = self
            .no_next_hop_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.remove(&format!("{sid}|{role}"));
    }

    /// Recompute the route table for the **active console-session user**
    /// (Free single-active-user model). `active_sids` is the routing-active
    /// set from `ActiveSidRegistry`; in Free at most one is active. With
    /// none active the table is torn down (no user → no routes; M-1).
    ///
    /// Resolves the active user's secondary target (binding × live adapter
    /// info) itself, so the wiring layer only has to forward the trigger.
    /// Pro (multiple concurrently-active users) would route per session via
    /// a callout driver; here the first active SID owns the global table.
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

    /// resolve everything the
    /// kill-switch needs about `sid`'s secondary interface: its LUID plus the
    /// system exemptions (VPN server IPs, primary local subnets).
    ///
    /// `None` when there is no usable secondary or its LUID can't be resolved
    /// (fail-open — no kill-switch this cycle). When `Some`, the server-IP set
    /// may still be empty (the caller's catch-all path refuses to arm in that
    /// case, to avoid trapping the tunnel's own reconnection); the
    /// per-destination path (mode A) ignores the exemptions entirely.
    ///
    /// Enumerates the route table once for both the bootstrap-server-IP and
    /// the local-subnet derivations, and caches the last-known server IPs so a
    /// reconnect blip (bootstrap route briefly gone) does not drop the
    /// exemption.
    pub fn kill_switch_exemptions(&self, sid: &str) -> Option<KillSwitchResolution> {
        let resolution = self.resolve(sid);
        let secondary = resolution.secondary?;
        let secondary_luid = match self.api.interface_luid_for_index(secondary.interface_index) {
            Ok(l) if l != 0 => l,
            Ok(_) => return None,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    ifindex = secondary.interface_index,
                    "kill-switch: could not resolve secondary LUID; staying off (fail-open): {e:?}",
                );
                return None;
            }
        };
        let routes = self.api.get_ip_forward_table().unwrap_or_default();
        let primary_gateway = resolution.primary.map(|p| p.gateway);
        let mut server_ips =
            bootstrap_server_ips(&routes, secondary.interface_index, primary_gateway);
        // Cache last-known server IPs (keyed by secondary ifindex). When the
        // live table yields none (VPN disconnected → bootstrap route gone),
        // fall back to the cache so the exemption — and thus reconnection —
        // survives.
        {
            let mut cache = self
                .server_ip_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if server_ips.is_empty() {
                if let Some(cached) = cache.get(&secondary.interface_index) {
                    server_ips = cached.clone();
                }
            } else {
                cache.insert(secondary.interface_index, server_ips.clone());
                // write-through so the observed server
                // IPs survive a service restart (the catch-all kill-switch will
                // not arm without a server exemption). Best-effort; the closure
                // logs+swallows any storage error. Invoked outside the DB lock.
                if let Some(persist) = self.server_ip_persist.as_ref() {
                    persist(&server_ips);
                }
            }
        }
        let local_subnets = resolution
            .primary
            .map(|p| primary_local_subnets(&routes, p.interface_index))
            .unwrap_or_default();
        // Reactive VPN-endpoint learning — fold in any role-verified server IP
        // learned from a kill-switch drop (deduped against the route-observed
        // set above), so the catch-all pair (and the mirrored per-IP subtract
        // in `per_sid_orchestrator`) exempt it exactly like an observed one.
        if let Some(learned) = self.learned_vpn_endpoints.as_ref() {
            for ip in learned.current(std::time::SystemTime::now()) {
                if !server_ips.contains(&ip) {
                    server_ips.push(ip);
                }
            }
        }
        Some(KillSwitchResolution {
            secondary_luid,
            bootstrap_server_ips: server_ips,
            local_subnets,
        })
    }

    /// exemptions for the **fail-closed** block-all path
    /// (mode B) when the secondary cannot be resolved. Unlike
    /// [`Self::kill_switch_exemptions`] this never returns `None`: the whole
    /// point is to arm a block-all even when the secondary is gone. It resolves the
    /// PRIMARY (the working link) independently and returns its connected
    /// subnets so the block-all keeps LAN / local manageability, plus any
    /// cached VPN-server IPs (best-effort) so the tunnel can reconnect.
    pub fn fail_closed_exemptions(&self, sid: &str) -> FailClosedExemptions {
        let resolution = self.resolve(sid);
        let routes = self.api.get_ip_forward_table().unwrap_or_default();
        let local_subnets = resolution
            .primary
            .map(|p| primary_local_subnets(&routes, p.interface_index))
            .unwrap_or_default();
        // Best-effort: exempt every VPN-server IP we have ever cached (we do
        // not know which secondary ifindex applies when it is unresolved).
        // Exempting a stale server is harmless — it only permits a little more.
        //
        // union the PERSISTED server IPs (from a prior
        // run) with the live in-memory cache, deduped. After a service restart the
        // in-memory cache is empty until the VPN reconnects, so without the seed
        // the block-all would have no server hole and could not arm; the persisted
        // set keeps the tunnel able to reconnect through the fail-closed block.
        let bootstrap_server_ips = {
            let mut seen = std::collections::HashSet::new();
            let mut ips: Vec<Ipv4Addr> = self
                .server_ip_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .values()
                .flatten()
                .copied()
                .filter(|ip| seen.insert(*ip))
                .collect();
            if let Some(loader) = self.server_ip_loader.as_ref() {
                ips.extend(loader().into_iter().filter(|ip| seen.insert(*ip)));
            }
            // Reactive VPN-endpoint learning — fold in any role-verified
            // server IP learned from a kill-switch drop, deduped against the
            // cached/persisted set above (see `kill_switch_exemptions` for the
            // twin merge on the secondary-resolved path).
            if let Some(learned) = self.learned_vpn_endpoints.as_ref() {
                ips.extend(
                    learned
                        .current(std::time::SystemTime::now())
                        .into_iter()
                        .filter(|ip| seen.insert(*ip)),
                );
            }
            ips
        };
        // The liveness probe's ICMP target: the secondary's RAW next-hop,
        // resolved WITHOUT the liveness gate. A probe-DEAD verdict empties the
        // gated resolution — which is exactly when the block-all arms — yet the
        // probe must keep reaching the next-hop or its verdict can never flip
        // back to healthy and the block-all never disarms  HW
        // diagnosis). The echo is kernel-originated (no app-id), so only this
        // destination exemption can cover it.
        let probe_target_ips = match resolution.secondary {
            Some(t) => vec![t.gateway],
            None => self
                .route_source
                .load_for_sid(sid)
                .and_then(|policy| {
                    let binding = policy.secondary.as_ref()?;
                    let infos = self.api.get_adapter_infos().ok()?;
                    self.resolve_binding_target(sid, binding, &infos, "secondary")
                })
                .map(|t| vec![t.gateway])
                .unwrap_or_default(),
        };
        FailClosedExemptions {
            bootstrap_server_ips,
            local_subnets,
            // the resolver has no rule/codegen context;
            // the orchestrator fills known-primary IPs at the block-all call site.
            primary_dest_ips: Vec::new(),
            // the resolver returns the strict default; the orchestrator
            // overrides this from the per-SID policy at the block-all call site.
            allow_dns_over_primary: false,
            // the orchestrator fills known-direct IPs at the block-all
            // call site (it owns the registry and the secondary-dest subtraction).
            known_direct_ips: Vec::new(),
            probe_target_ips,
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
        // (a GUID-churning VPN like hidemy.name can leave a stale/down TAP instance
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
                let ambiguous = healed.next().is_some();
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
                            }
                            None => {
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
                        self.next_hop_cache
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .insert(info.index, nh);
                        // Expected for VPN tunnels — debug, not warn, so it
                        // does not spam the steady-state log every cycle.
                        tracing::debug!(
                            target: "nrr::route-coordinator",
                            sid = %sid,
                            role = role,
                            ifindex = info.index,
                            next_hop = %nh,
                            "bound adapter exposes no gateway; derived tunnel next-hop from its catch-all routes",
                        );
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
                    self.probed_ifindex
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(sid.clone(), t.interface_index);
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
            // resolve() already logged the specific reason.
            return self.reconciler.clear();
        };
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
        let shared_ip_policy = self
            .route_source
            .load_for_sid(sid)
            .map(|p| p.shared_ip_policy)
            .unwrap_or_default();
        let denied = crate::secondary_ip_policy::secondary_ip_denylist(
            &snapshot.rule_book.secondary,
            self.fqdn_cache.as_ref(),
            shared_ip_policy,
        );
        let mut out = generate_routes(
            resolution.mode,
            &snapshot.rule_book,
            resolution.primary.as_ref(),
            &secondary,
            self.fqdn_cache.as_ref(),
            self.app_observations.as_ref(),
            &denied,
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
            tracing::debug!(
                target: "nrr::route-coordinator",
                sid = %sid,
                diagnostics = out.diagnostics.len(),
                routes = out.routes.len(),
                "route codegen produced diagnostics (cold cache / app-routing-pro / no primary target)",
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
        // DISABLED after hardware testing.
        // `strip_foreign_overlay` (removing the VPN client's redirect `/1`)
        // destabilises real VPN clients: hidemy.name's OpenVPN treated the route
        // removal as a fault and forced reconnects, and in mode A it dropped
        // not-yet-resolved hosts (DoH-only domains with no `/32`) to the primary
        // with the real IP. We stay ADD-ONLY: never remove the VPN's routes;
        // our `/32` rules (and the mode-B overlay) ride on top. Mode-A
        // selectivity ("non-rule → primary") will instead use a `/2`
        // counter-overlay via primary (more specific than the VPN's `/1`,
        // no removal → no tunnel disruption) — see project notes.
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
                // Both owned shapes ride SECONDARY_ROUTE_METRIC: the `/32`
                // secondary host routes and the `/2` mode-A counter-overlay.
                r.metric == crate::route_codegen::SECONDARY_ROUTE_METRIC
                    && (r.prefix_length == 32 || r.prefix_length == 2)
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
                    || (active.is_empty() && sid == nrr_domain::user_principal::BASELINE_PRINCIPAL)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use crate::per_sid_orchestrator::ActiveRulesSnapshot;
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::{RouteBehaviorMode, RuleId};
    use nrr_platform_api::MockWindowsApi;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Fake provider returning a per-SID snapshot from an in-memory map,
    /// with read-through to a baseline entry under the `"__baseline__"`
    /// key (mirrors the production provider's contract closely enough for
    /// the coordinator's purposes).
    struct FakeRules {
        by_sid: Mutex<std::collections::HashMap<String, CanonicalRuleSet>>,
    }
    impl FakeRules {
        fn new() -> Self {
            Self {
                by_sid: Mutex::new(std::collections::HashMap::new()),
            }
        }
        fn set_secondary(&self, sid: &str, secondary: CanonicalRuleSet) {
            self.by_sid
                .lock()
                .unwrap()
                .insert(sid.to_string(), secondary);
        }
    }
    impl RulesProvider for FakeRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            self.active_rules_for("__baseline__")
        }
        fn active_rules_for(&self, principal: &str) -> Option<ActiveRulesSnapshot> {
            let g = self.by_sid.lock().unwrap();
            let secondary = g
                .get(principal)
                .or_else(|| g.get("__baseline__"))
                .cloned()?;
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(vec![]),
                    secondary,
                },
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    fn ip_rule(id: &str, a: u8, b: u8, c: u8, d: u8) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(Ipv4Addr::new(a, b, c, d))),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn target() -> SecondaryRouteTarget {
        SecondaryRouteTarget {
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            interface_index: 7,
        }
    }

    /// Mode-A resolution with the given secondary target (no primary), for the
    /// `recompute_for` tests that exercise the secondary `/32` path.
    fn res(secondary: Option<SecondaryRouteTarget>) -> RouteResolution {
        RouteResolution {
            mode: RouteBehaviorMode::PreferPrimary,
            primary: None,
            secondary,
        }
    }

    fn table_dests(api: &MockWindowsApi) -> HashSet<Ipv4Addr> {
        api.get_ip_forward_table()
            .unwrap()
            .iter()
            .map(|r| r.destination)
            .collect()
    }

    /// In-memory `RoutePolicySource` mapping SID → secondary `stable_id`.
    struct FakePolicy {
        by_sid: Mutex<std::collections::HashMap<String, String>>,
        primary_by_sid: Mutex<std::collections::HashMap<String, String>>,
        secondary_names: Mutex<std::collections::HashMap<String, String>>,
    }
    impl FakePolicy {
        fn new() -> Self {
            Self {
                by_sid: Mutex::new(std::collections::HashMap::new()),
                primary_by_sid: Mutex::new(std::collections::HashMap::new()),
                secondary_names: Mutex::new(std::collections::HashMap::new()),
            }
        }
        fn bind_secondary(&self, sid: &str, stable_id: &str) {
            self.by_sid
                .lock()
                .unwrap()
                .insert(sid.to_string(), stable_id.to_string());
        }
        /// Bind a secondary with a saved display_name (drives the stale-id
        /// auto-heal, which matches by name).
        fn bind_secondary_named(&self, sid: &str, stable_id: &str, display_name: &str) {
            self.bind_secondary(sid, stable_id);
            self.secondary_names
                .lock()
                .unwrap()
                .insert(sid.to_string(), display_name.to_string());
        }
        fn bind_primary(&self, sid: &str, stable_id: &str) {
            self.primary_by_sid
                .lock()
                .unwrap()
                .insert(sid.to_string(), stable_id.to_string());
        }
    }
    impl RoutePolicySource for FakePolicy {
        fn load_for_sid(
            &self,
            sid: &str,
        ) -> Option<crate::per_sid_orchestrator::PerSidPolicySnapshot> {
            use crate::per_sid_orchestrator::{PerSidBinding, PerSidPolicySnapshot};
            let stable = self.by_sid.lock().unwrap().get(sid).cloned()?;
            let primary = self
                .primary_by_sid
                .lock()
                .unwrap()
                .get(sid)
                .cloned()
                .map(|id| PerSidBinding {
                    stable_id: id,
                    display_name: String::new(),
                    user_confirmed: true,
                    known_stable_ids: Vec::new(),
                });
            let secondary_name = self
                .secondary_names
                .lock()
                .unwrap()
                .get(sid)
                .cloned()
                .unwrap_or_default();
            Some(PerSidPolicySnapshot {
                primary,
                secondary: Some(PerSidBinding {
                    stable_id: stable,
                    display_name: secondary_name,
                    user_confirmed: true,
                    known_stable_ids: Vec::new(),
                }),
                mode: crate::per_sid_orchestrator::PerSidBehaviorMode::PreferPrimary,
                block_secondary_when_unavailable: false,
                kill_switch_fail_closed: true,
                kill_switch_protocols: 0x7F,
                kill_switch_block_all: false,
                // this fake feeds route-coordinator tests that assert the
                // armed leak-guard path; keep the master toggle ON so their
                // expectations hold under the new opt-in gate.
                kill_switch_enabled: true,
                allow_dns_over_primary: false,
                shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
                kill_switch_strict_shared_ips: true,
                mode_a_coverage_strategy:
                    nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
                link_provider_exe_paths: Vec::new(),
                doh_lockdown_enabled: false,
                doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
                doh_resolver_ips: Vec::new(),
                auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            })
        }
    }

    fn coordinator(api: Arc<MockWindowsApi>, rules: Arc<FakeRules>) -> SecondaryRouteCoordinator {
        SecondaryRouteCoordinator::new(
            api as Arc<dyn WindowsApiPort>,
            rules as Arc<dyn RulesProvider>,
            Arc::new(FakePolicy::new()) as Arc<dyn RoutePolicySource>,
            Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
            Arc::new(|| false) as RuleScopeProvider,
        )
    }

    fn coordinator_with_policy(
        api: Arc<MockWindowsApi>,
        rules: Arc<FakeRules>,
        policy: Arc<FakePolicy>,
    ) -> SecondaryRouteCoordinator {
        SecondaryRouteCoordinator::new(
            api as Arc<dyn WindowsApiPort>,
            rules as Arc<dyn RulesProvider>,
            policy as Arc<dyn RoutePolicySource>,
            Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
            Arc::new(|| false) as RuleScopeProvider,
        )
    }

    fn coordinator_with_scope(
        api: Arc<MockWindowsApi>,
        rules: Arc<FakeRules>,
        service_driven: bool,
    ) -> SecondaryRouteCoordinator {
        SecondaryRouteCoordinator::new(
            api as Arc<dyn WindowsApiPort>,
            rules as Arc<dyn RulesProvider>,
            Arc::new(FakePolicy::new()) as Arc<dyn RoutePolicySource>,
            Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
            Arc::new(move || service_driven) as RuleScopeProvider,
        )
    }

    #[test]
    fn fail_closed_exemptions_seed_persisted_server_ips_before_reconnect() {
        // after a restart the in-memory server_ip_cache is
        // empty (the VPN has not reconnected), but the persisted loader seeds the
        // fail-closed exemptions so the block-all can still arm with a server hole.
        let api = Arc::new(MockWindowsApi::new());
        let persisted = Ipv4Addr::new(203, 0, 113, 77);
        let coord = coordinator(Arc::clone(&api), Arc::new(FakeRules::new()))
            .with_bootstrap_server_persistence(
                Arc::new(|_ips: &[Ipv4Addr]| {}),
                Arc::new(move || vec![persisted]),
            );
        let ex = coord.fail_closed_exemptions("S-1-5-21-A");
        assert!(
            ex.bootstrap_server_ips.contains(&persisted),
            "persisted server IP seeds the fail-closed exemption before any live observation",
        );
    }

    #[test]
    fn fail_closed_exemptions_without_persistence_is_unchanged() {
        // No persistence wired → empty exemption server set (prior behaviour).
        let api = Arc::new(MockWindowsApi::new());
        let coord = coordinator(api, Arc::new(FakeRules::new()));
        let ex = coord.fail_closed_exemptions("S-1-5-21-A");
        assert!(ex.bootstrap_server_ips.is_empty());
        assert!(ex.probe_target_ips.is_empty());
    }

    #[test]
    fn fail_closed_exemptions_carry_probe_target_even_when_liveness_dead() {
        //  HW — the block-all must keep a hole for the liveness
        // probe's ICMP target (the tunnel next-hop). A probe-DEAD verdict
        // empties the GATED resolution — which is exactly when the block-all
        // arms — so the exemption must come from the RAW binding resolution,
        // or the armed block eats the probe's echo and the DEAD verdict can
        // never flip back (the kill-switch would stay fail-closed through
        // every VPN reconnect until service restart).
        let sid = "S-1-5-21-A";
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let api = Arc::new(MockWindowsApi::new());
        let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
        let vpn_id = vpn.stable_id();
        api.set_adapter_infos(vec![vpn]);
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary(sid, &vpn_id);

        // Alive tunnel (liveness disabled) → the gated resolution carries the
        // target and so must the exemptions.
        let coord = coordinator_with_policy(
            Arc::clone(&api),
            Arc::new(FakeRules::new()),
            Arc::clone(&policy),
        );
        assert_eq!(coord.fail_closed_exemptions(sid).probe_target_ips, vec![gw]);

        // Probe-DEAD tunnel: a failure run older than the whole window makes
        // `is_dead` true, the gated resolution loses the secondary, and the
        // exemptions must still carry the raw next-hop.
        let tracker = Arc::new(SecondaryLivenessTracker::new(1));
        let dead_since = Instant::now()
            .checked_sub(std::time::Duration::from_secs(10))
            .expect("test host has been up for at least ten seconds");
        // Baseline first: a DEAD verdict requires the peer to have answered
        // at least once (silent-from-birth gateways are unprobeable, not
        // dead) — and the evidence must be FRESH (records within the
        // evidence gap of "now"), so the failing run is recorded up to the
        // present rather than left in the past.
        tracker.record(78, true, dead_since);
        tracker.record(78, false, dead_since);
        tracker.record(78, false, Instant::now());
        assert!(tracker.is_dead(78, Instant::now()), "fixture must be DEAD");
        let coord_dead =
            coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy)
                .with_liveness_probe(
                    tracker,
                    Arc::new(nrr_platform_api::reachability::AlwaysReachableProbe),
                );
        assert_eq!(
            coord_dead.fail_closed_exemptions(sid).probe_target_ips,
            vec![gw],
            "DEAD verdict must not drop the probe-target exemption",
        );
    }

    #[test]
    fn probe_tick_forgets_the_failing_run_when_the_binding_stops_resolving() {
        //  HW — while a VPN reconnects, its adapter enumerates Down
        // (no IPv4) and the probe cannot run. The failing run accumulated just
        // before the outage must be dropped the moment the binding stops
        // resolving, or the stale window declares the tunnel DEAD the instant
        // it comes back Up and the kill-switch fail-closes a freshly
        // reconnected, working tunnel.
        let sid = "S-1-5-21-A";
        let api = Arc::new(MockWindowsApi::new());
        let vpn = adapter("hidemyvpn", 60, true, true, Some([10, 88, 0, 1]));
        let vpn_id = vpn.stable_id();
        api.set_adapter_infos(vec![vpn]);
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary(sid, &vpn_id);
        let tracker = Arc::new(SecondaryLivenessTracker::new(10));
        let probe = Arc::new(nrr_platform_api::reachability::MockReachabilityProbe::new(
            false,
        ));
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy)
            .with_liveness_probe(Arc::clone(&tracker), probe);
        let sids = vec![sid.to_string()];
        coord.probe_active_secondaries(&sids);
        assert!(
            tracker.in_failing_run(60),
            "a failed probe starts a failing run"
        );
        // The adapter drops (VPN mid-reconnect) → the binding stops resolving.
        api.set_adapter_infos(vec![adapter("hidemyvpn", 60, false, false, None)]);
        coord.probe_active_secondaries(&sids);
        assert!(
            !tracker.in_failing_run(60),
            "an unprobeable binding must forget the stale failing run"
        );
    }

    #[test]
    fn no_next_hop_warn_latch_dedups_until_cleared() {
        let api = Arc::new(MockWindowsApi::new());
        let coord = coordinator(api, Arc::new(FakeRules::new()));
        assert!(coord.note_no_next_hop_once("S", "secondary"));
        assert!(
            !coord.note_no_next_hop_once("S", "secondary"),
            "same spell stays deduped"
        );
        assert!(
            coord.note_no_next_hop_once("S", "primary"),
            "latch is per (sid, role)"
        );
        coord.clear_no_next_hop("S", "secondary");
        assert!(
            coord.note_no_next_hop_once("S", "secondary"),
            "a successful resolution re-arms the warn"
        );
    }

    #[test]
    fn effective_routing_sid_prefers_registry_then_console_under_service_driven() {
        // 1. A connected-tray SID always wins, regardless of scope/console.
        let api = Arc::new(MockWindowsApi::new());
        api.set_console_user_sid(Some("S-CONSOLE"));
        let coord_app = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), false);
        assert_eq!(
            coord_app.effective_routing_sid(&["S-TRAY".to_string()]),
            Some("S-TRAY".to_string()),
        );

        // 2. No tray + app-driven scope → None (the console is never consulted).
        assert_eq!(coord_app.effective_routing_sid(&[]), None);

        // 3. No tray + service-driven scope + a console session → the console user.
        let coord_sd = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), true);
        assert_eq!(
            coord_sd.effective_routing_sid(&[]),
            Some("S-CONSOLE".to_string()),
        );

        // 4. No tray + service-driven scope + no console session → None.
        let api_no_console = Arc::new(MockWindowsApi::new());
        let coord_sd2 = coordinator_with_scope(api_no_console, Arc::new(FakeRules::new()), true);
        assert_eq!(coord_sd2.effective_routing_sid(&[]), None);
    }

    #[test]
    fn effective_enforcement_sids_falls_back_to_console_only_when_no_tray() {
        // the WFP orchestrator's SID set.
        let api = Arc::new(MockWindowsApi::new());
        api.set_console_user_sid(Some("S-CONSOLE"));
        let coord = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), true);

        // 1. Connected trays pass through unchanged (incl. multi-tray) —
        //    the fallback never overrides them.
        let trays = vec!["S-TRAY-1".to_string(), "S-TRAY-2".to_string()];
        assert_eq!(coord.effective_enforcement_sids(&trays), trays);

        // 2. No tray + service-driven scope → the console user.
        assert_eq!(
            coord.effective_enforcement_sids(&[]),
            vec!["S-CONSOLE".to_string()],
        );

        // 3. No tray + app-driven scope → empty (nothing to enforce).
        let coord_app = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), false);
        assert!(coord_app.effective_enforcement_sids(&[]).is_empty());

        // 4. No tray + service-driven + no console session → empty.
        let coord_no_console = coordinator_with_scope(
            Arc::new(MockWindowsApi::new()),
            Arc::new(FakeRules::new()),
            true,
        );
        assert!(coord_no_console.effective_enforcement_sids(&[]).is_empty());
    }

    #[test]
    fn note_heal_once_dedups_until_mapping_changes() {
        let coord = coordinator(Arc::new(MockWindowsApi::new()), Arc::new(FakeRules::new()));
        let sid = "S-1-5-21-x-1001";
        // First sighting of a stale→healed mapping logs.
        assert!(coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new}"));
        // Same mapping repeats → silent (the heal re-fires every reconcile).
        assert!(!coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new}"));
        // Healed id changes (adapter reinstalled again) → logs once more.
        assert!(coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new2}"));
        assert!(!coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new2}"));
        // A different role under the same sid is tracked independently.
        assert!(coord.note_heal_once(sid, "primary", "win-adapter:{old}", "win-adapter:{new2}"));
    }

    #[test]
    fn note_not_usable_once_dedups_until_cleared_or_changed() {
        let coord = coordinator(Arc::new(MockWindowsApi::new()), Arc::new(FakeRules::new()));
        let sid = "S-1-5-21-x-1002";
        // First sighting of the not-usable state logs.
        assert!(coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
        // Same not-usable spell (adapter still down) repeats → silent.
        assert!(!coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
        assert!(!coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
        // Adapter resolves usable again → re-arm.
        coord.clear_not_usable(sid, "secondary");
        // Next not-usable transition for the SAME adapter logs again.
        assert!(coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
        // A different role under the same sid is tracked independently.
        assert!(coord.note_not_usable_once(sid, "primary", "win-adapter:{tap}"));
    }

    #[test]
    fn auto_heal_persists_corrected_binding_once() {
        // The stored secondary id is stale (adapter reinstalled → new GUID) but
        // the saved name still matches exactly one live adapter → auto-heal +
        // persist the corrected id, ONCE per distinct mapping (HW-0705).
        let api = Arc::new(MockWindowsApi::new());
        // Live adapter: new name/GUID "newguid", description "desc newguid",
        // up + IPv4 + gateway → Available and usable.
        let live = adapter("newguid", 59, true, true, Some([10, 0, 0, 1]));
        api.set_adapter_infos(vec![live]);

        let policy = Arc::new(FakePolicy::new());
        // Stale stored id; saved name "desc newguid" is a token-subset of the
        // live description, so the heal matches it.
        policy.bind_secondary_named("S-HEAL", "win-adapter:{oldguid}", "desc newguid");

        // Capture each persist as one "sid|role|id|name" line (a flat Vec keeps
        // the closure type simple for clippy::type_complexity).
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = Arc::clone(&captured);
        let coord = coordinator_with_policy(
            Arc::clone(&api),
            Arc::new(FakeRules::new()),
            Arc::clone(&policy),
        )
        .with_binding_heal_persist(Arc::new(move |sid, role, id, name| {
            cap.lock()
                .unwrap()
                .push(format!("{sid}|{role}|{id}|{name}"));
        }));

        // First resolution heals and persists exactly once.
        let r1 = coord.resolve("S-HEAL");
        assert!(r1.secondary.is_some(), "heal should yield a usable target");
        {
            let c = captured.lock().unwrap();
            assert_eq!(c.len(), 1, "persist fires once on first heal");
            assert_eq!(
                c[0], "S-HEAL|secondary|win-adapter:newguid|desc newguid",
                "healed id + name persisted for the secondary role"
            );
        }
        // Re-resolving the SAME stale→healed mapping must NOT persist again
        // (note_heal_once dedup) — no per-reconcile write storm.
        let _ = coord.resolve("S-HEAL");
        assert_eq!(
            captured.lock().unwrap().len(),
            1,
            "repeated heal of the same mapping does not re-persist"
        );
    }

    #[test]
    fn found_but_down_bound_adapter_heals_to_available_same_name_sibling() {
        // the bound GUID is still ENUMERATED but DOWN (a GUID-churning
        // VPN can leave a stale/down TAP instance visible while the freshly-connected
        // one carries traffic). The resolver must heal to the live same-name SIBLING
        // instead of failing closed on the down instance.
        let api = Arc::new(MockWindowsApi::new());
        // `down` = the bound (present-but-down) instance; `sibling` = a live
        // same-family adapter whose version token differs.
        let mut down = adapter("oldtap", 1, false, false, None);
        down.description = "hidemy vpn 3.0 adapter".into();
        down.friendly_name = down.description.clone();
        let mut sibling = adapter("newtap", 2, true, true, Some([10, 0, 0, 1]));
        sibling.description = "hidemy vpn adapter".into();
        sibling.friendly_name = sibling.description.clone();
        api.set_adapter_infos(vec![down, sibling]);

        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary_named("S-DOWN", "win-adapter:oldtap", "hidemy vpn 3.0 adapter");

        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = Arc::clone(&captured);
        let coord = coordinator_with_policy(
            Arc::clone(&api),
            Arc::new(FakeRules::new()),
            Arc::clone(&policy),
        )
        .with_binding_heal_persist(Arc::new(move |sid, role, id, name| {
            cap.lock()
                .unwrap()
                .push(format!("{sid}|{role}|{id}|{name}"));
        }));

        let r = coord.resolve("S-DOWN");
        assert!(
            r.secondary.is_some(),
            "a present-but-down bound adapter must heal to the live same-name sibling, not fail closed"
        );
        let c = captured.lock().unwrap();
        assert_eq!(c.len(), 1, "the healed sibling id is persisted once");
        assert_eq!(
            c[0],
            "S-DOWN|secondary|win-adapter:newtap|hidemy vpn adapter"
        );
    }

    #[test]
    fn recompute_applies_active_users_secondary_routes() {
        let api = Arc::new(MockWindowsApi::new());
        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![
                ip_rule("r1", 1, 1, 1, 1),
                ip_rule("r2", 2, 2, 2, 2),
            ]),
        );
        let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

        let delta = coord
            .recompute_for("S-IVANOV", &res(Some(target())))
            .unwrap();
        assert_eq!(delta.added, 2);
        assert_eq!(
            table_dests(&api),
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)])
        );
    }

    #[test]
    fn switching_active_user_replaces_the_route_table() {
        let api = Arc::new(MockWindowsApi::new());
        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
        );
        rules.set_secondary(
            "S-PETROV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r2", 2, 2, 2, 2)]),
        );
        let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

        coord
            .recompute_for("S-IVANOV", &res(Some(target())))
            .unwrap();
        assert_eq!(
            table_dests(&api),
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1)])
        );

        // Petrov logs in (becomes active) → Ivanov's routes torn down,
        // Petrov's installed. The machine-wide table follows the active user.
        coord
            .recompute_for("S-PETROV", &res(Some(target())))
            .unwrap();
        assert_eq!(
            table_dests(&api),
            HashSet::from([Ipv4Addr::new(2, 2, 2, 2)])
        );
    }

    #[test]
    fn no_secondary_target_tears_down_routes() {
        let api = Arc::new(MockWindowsApi::new());
        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
        );
        let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
        coord
            .recompute_for("S-IVANOV", &res(Some(target())))
            .unwrap();
        assert_eq!(coord.owned_count(), 1);

        // Secondary goes away (unbound / adapter down) → routes removed.
        let delta = coord.recompute_for("S-IVANOV", &res(None)).unwrap();
        assert_eq!(delta.removed, 1);
        assert!(table_dests(&api).is_empty());
    }

    #[test]
    fn recompute_active_tears_down_when_effective_sid_paused() {
        // Safe-disable ROUTE-half — when the pause predicate reports the
        // effective routing SID paused, `recompute_active` returns a clear()
        // delta and installs no routes, even though rules + a usable secondary
        // would otherwise produce a /32. The gate sits in the single re-drive
        // choke point (recompute_active), so every trigger honours it.
        use std::sync::atomic::{AtomicBool, Ordering};
        let api = Arc::new(MockWindowsApi::new());
        // A live, usable secondary adapter so resolve() yields a route target.
        let live = adapter("vpn", 7, true, true, Some([10, 0, 0, 1]));
        let bind_id = format!("win-adapter:{}", live.adapter_name);
        api.set_adapter_infos(vec![live]);

        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
        );
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary("S-IVANOV", &bind_id);

        let paused = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&paused);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy)
            .with_pause_state(Arc::new(move |_sid: &str| {
                if flag.load(Ordering::SeqCst) {
                    PausedRouteDisposition::ClearAll
                } else {
                    PausedRouteDisposition::Active
                }
            }));

        // Not paused → the /32 secondary route installs.
        coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
        assert_eq!(coord.owned_count(), 1);
        assert_eq!(
            table_dests(&api),
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1)])
        );

        // Pause the effective routing user (teardown policy) → the next recompute
        // (via ANY re-drive path) tears the route table down instead of
        // reinstalling.
        paused.store(true, Ordering::SeqCst);
        let delta = coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
        assert_eq!(delta.removed, 1);
        assert_eq!(coord.owned_count(), 0);
        assert!(table_dests(&api).is_empty());
    }

    #[test]
    fn recompute_active_keeps_slash32_when_paused_persist() {
        // Safe-disable ROUTE-half — when the paused user's stop-policy is
        // Persist, the recompute gate must KEEP the
        // /32 secondary rule-routes (it drops only overlays), NOT full-clear them.
        // Before the fix the 30 s safety tick returned clear() unconditionally,
        // silently deleting the /32s `teardown_routes` deliberately kept and
        // defeating the Persist opt-in within ~30 s of pausing.
        use std::sync::atomic::{AtomicBool, Ordering};
        let api = Arc::new(MockWindowsApi::new());
        let live = adapter("vpn", 7, true, true, Some([10, 0, 0, 1]));
        let bind_id = format!("win-adapter:{}", live.adapter_name);
        api.set_adapter_infos(vec![live]);

        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
        );
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary("S-IVANOV", &bind_id);

        let paused = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&paused);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy)
            .with_pause_state(Arc::new(move |_sid: &str| {
                if flag.load(Ordering::SeqCst) {
                    PausedRouteDisposition::KeepSecondaryHosts
                } else {
                    PausedRouteDisposition::Active
                }
            }));

        // Not paused → the /32 secondary route installs.
        coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
        assert_eq!(coord.owned_count(), 1);

        // Pause with Persist policy → the safety-tick recompute KEEPS the /32.
        paused.store(true, Ordering::SeqCst);
        coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
        assert_eq!(
            coord.owned_count(),
            1,
            "Persist keeps the /32 rule-route across a paused re-drive"
        );
        assert_eq!(
            table_dests(&api),
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1)]),
            "the matched host still egresses the secondary under Persist pause"
        );
    }

    fn adapter(
        stable_seed: &str,
        idx: u32,
        up: bool,
        ipv4: bool,
        gw: Option<[u8; 4]>,
    ) -> AdapterInfo {
        use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
        AdapterInfo {
            index: idx,
            adapter_name: stable_seed.into(),
            description: format!("desc {stable_seed}"),
            // Fixture default: the connection carries the driver name, so tests
            // that do not care about the distinction see one name.
            friendly_name: format!("desc {stable_seed}"),
            mac: Some([0, 1, 2, 3, 4, idx as u8]),
            interface_type: InterfaceType::Ethernet,
            oper_status: if up {
                IfOperStatus::Up
            } else {
                IfOperStatus::Down
            },
            ipv4_addresses: if ipv4 {
                vec![Ipv4Addr::new(192, 168, 1, 50)]
            } else {
                vec![]
            },
            gateways: gw.map(|g| vec![Ipv4Addr::from(g)]).unwrap_or_default(),
        }
    }

    #[test]
    fn resolve_secondary_target_picks_gateway_and_ifindex_for_usable_adapter() {
        let a = adapter("wifi", 12, true, true, Some([10, 0, 0, 1]));
        let sid = a.stable_id();
        let t = resolve_secondary_target(&sid, std::slice::from_ref(&a)).unwrap();
        assert_eq!(t.interface_index, 12);
        assert_eq!(t.gateway, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn resolve_secondary_target_none_when_down_or_no_gateway_or_unknown() {
        let down = adapter("d", 1, false, true, Some([10, 0, 0, 1]));
        assert!(resolve_secondary_target(&down.stable_id(), std::slice::from_ref(&down)).is_none());
        let no_gw = adapter("g", 2, true, true, None);
        assert!(
            resolve_secondary_target(&no_gw.stable_id(), std::slice::from_ref(&no_gw)).is_none()
        );
        let usable = adapter("u", 3, true, true, Some([10, 0, 0, 1]));
        assert!(resolve_secondary_target("no-such-id", std::slice::from_ref(&usable)).is_none());
    }

    fn route_entry(
        dest: [u8; 4],
        prefix: u8,
        next_hop: [u8; 4],
        ifindex: u32,
        metric: u32,
    ) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(dest),
            prefix_length: prefix,
            next_hop: Ipv4Addr::from(next_hop),
            interface_index: ifindex,
            metric,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    #[test]
    fn derives_tunnel_next_hop_from_redirect_gateway_split_routes() {
        // Mirrors a live hidemy.name OpenVPN table: split-default via the
        // peer 10.91.192.1, no adapter gateway, on ifindex 78.
        let routes = vec![
            route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
            route_entry([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
            route_entry([10, 91, 193, 99], 32, [0, 0, 0, 0], 78, 256), // on-link → ignored
            route_entry([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, 25),    // other ifindex → ignored
        ];
        assert_eq!(
            derive_secondary_next_hop(&routes, 78),
            Some(Ipv4Addr::new(10, 91, 192, 1))
        );
        // No default-style route on an unrelated ifindex → None.
        assert_eq!(derive_secondary_next_hop(&routes, 999), None);
    }

    #[test]
    fn derive_prefers_real_default_over_split_halves() {
        let routes = vec![
            route_entry([0, 0, 0, 0], 1, [10, 0, 0, 1], 5, 1), // /1 split half
            route_entry([0, 0, 0, 0], 0, [10, 0, 0, 9], 5, 50), // real /0 default — wins despite higher metric
        ];
        assert_eq!(
            derive_secondary_next_hop(&routes, 5),
            Some(Ipv4Addr::new(10, 0, 0, 9))
        );
    }

    #[test]
    fn derive_ignores_on_link_and_loopback_but_falls_back_to_gateway_style_routes() {
        // On-link and loopback rows can never name a peer.
        let dead_ends = vec![
            route_entry([0, 0, 0, 0], 1, [0, 0, 0, 0], 5, 1), // on-link (unspecified next-hop)
            route_entry([0, 0, 0, 0], 0, [127, 0, 0, 1], 5, 1), // loopback next-hop
        ];
        assert_eq!(derive_secondary_next_hop(&dead_ends, 5), None);
        //  — a non-default gateway-style route IS a last resort:
        // on a point-to-point tunnel it names the same single peer the
        // stripped catch-alls did.
        let with_host_route = vec![
            route_entry([10, 0, 0, 0], 8, [10, 0, 0, 1], 5, 1),
            route_entry([0, 0, 0, 0], 1, [0, 0, 0, 0], 5, 1),
        ];
        assert_eq!(
            derive_secondary_next_hop(&with_host_route, 5),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn derive_primary_target_picks_lowest_metric_default_off_secondary() {
        let routes = vec![
            route_entry([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, 25), // real default on eth (ifx 12)
            route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),  // VPN /1 half → wrong prefix
            route_entry([0, 0, 0, 0], 0, [10, 91, 192, 1], 78, 1), // VPN /0 on secondary → excluded
            route_entry([0, 0, 0, 0], 0, [192, 168, 1, 254], 12, 5), // lower-metric default → wins
        ];
        let t = derive_primary_target(&routes, 78).expect("primary derived from OS default");
        assert_eq!(t.interface_index, 12);
        assert_eq!(t.gateway, Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn derive_primary_target_none_when_only_secondary_has_default() {
        // The VPN replaced /0 itself; nothing left to derive → None (caller warns).
        let routes = vec![route_entry([0, 0, 0, 0], 0, [10, 91, 192, 1], 78, 1)];
        assert!(derive_primary_target(&routes, 78).is_none());
    }

    #[test]
    fn recompute_mode_a_emits_counter_overlay_via_derived_primary() {
        // The footgun: user binds ONLY the secondary (VPN), picks "direct"
        // (mode A). The /2 counter-overlay (so unmatched → real link) needs a
        // primary; we derive it from the OS default route. Without this fix,
        // unmatched traffic silently rode the VPN's redirect.
        let api = Arc::new(MockWindowsApi::new());
        let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
        let vpn_id = vpn.stable_id();
        api.set_adapter_infos(vec![vpn]);
        api.set_route_table(vec![
            route_entry([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, 25), // OS default on eth
        ]);
        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r1", 93, 184, 216, 34)]),
        );
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary("S-IVANOV", &vpn_id); // ONLY secondary bound
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

        coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();

        let table = api.get_ip_forward_table().unwrap();
        let counter: Vec<_> = table.iter().filter(|r| r.prefix_length == 2).collect();
        assert_eq!(
            counter.len(),
            4,
            "four /2 counter-overlay routes must be installed via the derived primary"
        );
        assert!(
            counter
                .iter()
                .all(|r| r.interface_index == 12 && r.next_hop == Ipv4Addr::new(192, 168, 1, 1)),
            "counter-overlay must route via the derived primary gateway, not the secondary"
        );
    }

    #[test]
    fn recompute_active_routes_via_derived_next_hop_for_gatewayless_vpn() {
        // End-to-end: a gateway-less VPN adapter (the round-6 dead end) must
        // now route — resolve_target derives the tunnel peer from the route
        // table and the /32 overlay is installed via it.
        let api = Arc::new(MockWindowsApi::new());
        let vpn = adapter("hidemyvpn", 78, true, true, None); // up, IPv4, NO gateway
        let bound_id = vpn.stable_id();
        api.set_adapter_infos(vec![vpn]);
        api.set_route_table(vec![
            route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
            route_entry([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        ]);

        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r1", 93, 184, 216, 34)]),
        );
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary("S-IVANOV", &bound_id);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

        let delta = coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
        assert_eq!(delta.added, 1, "the /32 overlay must be installed");

        let table = api.get_ip_forward_table().unwrap();
        let ours = table
            .iter()
            .find(|r| r.destination == Ipv4Addr::new(93, 184, 216, 34))
            .expect("our /32 overlay must be present");
        assert_eq!(
            ours.next_hop,
            Ipv4Addr::new(10, 91, 192, 1),
            "must use the derived tunnel next-hop, not a (missing) adapter gateway"
        );
        assert_eq!(ours.interface_index, 78);
    }

    #[test]
    fn cache_keeps_routes_when_vpn_catch_all_vanishes() {
        // Add-only world (the C2 strip is disabled): if the VPN's catch-all
        // routes briefly vanish — e.g. a reconnect blip — derivation fails, but
        // the cached next-hop keeps our /32 routes alive instead of tearing them
        // down. Guards the gateway-less-VPN next-hop cache.
        let api = Arc::new(MockWindowsApi::new());
        let vpn = adapter("hidemyvpn", 78, true, true, None); // up, IPv4, NO gateway
        let bound_id = vpn.stable_id();
        api.set_adapter_infos(vec![vpn]);
        api.set_route_table(vec![
            route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
            route_entry([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        ]);
        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r1", 93, 184, 216, 34)]),
        );
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary("S-IVANOV", &bound_id);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

        // Cycle 1: derive the peer from the VPN's /1 (cached) + install the /32.
        coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
        assert!(
            api.get_ip_forward_table()
                .unwrap()
                .iter()
                .any(|r| r.destination == Ipv4Addr::new(93, 184, 216, 34)),
            "our /32 installed in cycle 1"
        );

        // The VPN's catch-all routes vanish (reconnect blip) — only our /32 left.
        api.set_route_table(vec![route_entry(
            [93, 184, 216, 34],
            32,
            [10, 91, 192, 1],
            78,
            5,
        )]);

        // Cycle 2: derivation fails (no catch-all) → cache fallback keeps the /32.
        coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
        assert!(
            api.get_ip_forward_table()
                .unwrap()
                .iter()
                .any(|r| r.destination == Ipv4Addr::new(93, 184, 216, 34)),
            "our /32 survives via the cached next-hop (NOT cleared)"
        );
    }

    #[test]
    fn resolve_secondary_luid_returns_luid_for_bound_usable_secondary() {
        // the coordinator hands the WFP
        // orchestrator the secondary interface LUID to pin its egress
        // condition to.
        let api = Arc::new(MockWindowsApi::new());
        let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
        let bound_id = vpn.stable_id();
        api.set_adapter_infos(vec![vpn]);
        let rules = Arc::new(FakeRules::new());
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary("S-IVANOV", &bound_id);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

        assert_eq!(
            coord.resolve_secondary_luid("S-IVANOV"),
            Some(nrr_platform_api::windows_api::mock_luid_for_index(78)),
            "must resolve the bound secondary's ifindex to its LUID",
        );
    }

    #[test]
    fn resolve_secondary_luid_none_when_no_usable_secondary() {
        // No secondary bound at all → None (fail-open: no kill-switch).
        let api = Arc::new(MockWindowsApi::new());
        let rules = Arc::new(FakeRules::new());
        let policy = Arc::new(FakePolicy::new());
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);
        assert_eq!(coord.resolve_secondary_luid("S-NOBODY"), None);
    }

    #[test]
    fn resolve_egress_source_ips_returns_the_adapters_own_addresses() {
        // The fake-IP relay binds its dials to these; each role must yield the
        // resolved adapter's OWN unicast address, and a down secondary must
        // yield None (the relay then refuses instead of leaking).
        let api = Arc::new(MockWindowsApi::new());
        let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
        let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
        let vpn_id = vpn.stable_id();
        let eth_id = eth.stable_id();
        api.set_adapter_infos(vec![vpn, eth]);
        let rules = Arc::new(FakeRules::new());
        let policy = Arc::new(FakePolicy::new());
        policy.bind_primary("S-IVANOV", &eth_id);
        policy.bind_secondary("S-IVANOV", &vpn_id);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

        let (primary, secondary) = coord.resolve_egress_source_ips("S-IVANOV");
        assert_eq!(primary, Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(secondary, Some(Ipv4Addr::new(192, 168, 1, 50)));

        // The secondary goes down → its source disappears, the primary stays.
        let vpn_down = adapter("hidemyvpn", 78, false, true, Some([10, 0, 0, 1]));
        let eth_up = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
        api.set_adapter_infos(vec![vpn_down, eth_up]);
        let (primary, secondary) = coord.resolve_egress_source_ips("S-IVANOV");
        assert_eq!(primary, Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(secondary, None);
    }

    #[test]
    fn kill_switch_exemptions_resolves_luid_servers_and_subnets() {
        // the coordinator derives the catch-all
        // exemptions: the secondary LUID, the VPN server IP (bootstrap host
        // route via the primary gateway), and the primary's connected subnet.
        let api = Arc::new(MockWindowsApi::new());
        let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
        let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
        let vpn_id = vpn.stable_id();
        let eth_id = eth.stable_id();
        api.set_adapter_infos(vec![vpn, eth]);
        api.set_route_table(vec![
            route_entry([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, 5), // VPN server bootstrap via eth gw
            route_entry([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, 5),     // primary connected subnet
            route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),      // VPN redirect half
        ]);
        let rules = Arc::new(FakeRules::new());
        let policy = Arc::new(FakePolicy::new());
        policy.bind_primary("S-IVANOV", &eth_id);
        policy.bind_secondary("S-IVANOV", &vpn_id);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

        let ex = coord
            .kill_switch_exemptions("S-IVANOV")
            .expect("exemptions resolve when secondary + primary are usable");
        assert_eq!(
            ex.secondary_luid,
            nrr_platform_api::windows_api::mock_luid_for_index(78)
        );
        assert_eq!(ex.bootstrap_server_ips, vec![Ipv4Addr::new(203, 0, 113, 7)]);
        assert_eq!(ex.local_subnets, vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]);
    }

    #[test]
    fn kill_switch_exemptions_cache_keeps_server_ip_after_bootstrap_route_vanishes() {
        // The VPN client drops the bootstrap route while disconnected; the
        // last-known server IP must survive (else reconnection deadlocks).
        let api = Arc::new(MockWindowsApi::new());
        let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
        let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
        let vpn_id = vpn.stable_id();
        let eth_id = eth.stable_id();
        api.set_adapter_infos(vec![vpn, eth]);
        api.set_route_table(vec![route_entry(
            [203, 0, 113, 7],
            32,
            [192, 168, 1, 1],
            12,
            5,
        )]);
        let rules = Arc::new(FakeRules::new());
        let policy = Arc::new(FakePolicy::new());
        policy.bind_primary("S-IVANOV", &eth_id);
        policy.bind_secondary("S-IVANOV", &vpn_id);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

        // Cycle 1: server IP present → cached.
        let ex1 = coord.kill_switch_exemptions("S-IVANOV").unwrap();
        assert_eq!(
            ex1.bootstrap_server_ips,
            vec![Ipv4Addr::new(203, 0, 113, 7)]
        );

        // Bootstrap route vanishes (VPN disconnected).
        api.set_route_table(vec![]);

        // Cycle 2: live table empty → cache fallback keeps the server IP.
        let ex2 = coord.kill_switch_exemptions("S-IVANOV").unwrap();
        assert_eq!(
            ex2.bootstrap_server_ips,
            vec![Ipv4Addr::new(203, 0, 113, 7)],
            "cached server IP must survive a bootstrap-route blip"
        );
    }

    #[test]
    fn description_matches_display_name_version_robust_and_symmetric() {
        // Live description carries an extra version token vs the saved name.
        assert!(description_matches_display_name(
            "hidemy.name VPN 3.0 OpenVPN Adapter",
            "hidemy.name VPN OpenVPN Adapter",
        ));
        // regression: the SAVED name carries the version token and the
        // live adapter dropped it — the "every other day" heal failure. The old
        // directional subset returned false here; symmetric containment heals it.
        assert!(description_matches_display_name(
            "hidemy.name VPN OpenVPN Adapter",
            "hidemy.name VPN 3.0 OpenVPN Adapter",
        ));
        // Both sides versioned, different versions → same family.
        assert!(description_matches_display_name(
            "hidemy.name VPN 4.1 OpenVPN Adapter",
            "hidemy.name VPN 3.0 OpenVPN Adapter",
        ));
        // Survives a version bump (saved has no version).
        assert!(description_matches_display_name(
            "hidemy.name VPN 4.1 OpenVPN Adapter",
            "hidemy.name VPN OpenVPN Adapter",
        ));
        // Case-insensitive.
        assert!(description_matches_display_name(
            "HIDEMY.NAME vpn openvpn ADAPTER",
            "hidemy.name VPN OpenVPN Adapter",
        ));
        // Different adapter → no match, both directions.
        assert!(!description_matches_display_name(
            "Intel(R) Ethernet Connection (2) I219-V",
            "hidemy.name VPN OpenVPN Adapter",
        ));
        assert!(!description_matches_display_name(
            "hidemy.name VPN OpenVPN Adapter",
            "Intel(R) Ethernet Connection (2) I219-V",
        ));
        // Empty / whitespace-only display_name never matches.
        assert!(!description_matches_display_name("anything at all", "   "));
        // A name reduced to ONLY a version token has an empty core → no match
        // (never heal to an adapter whose family is unidentifiable).
        assert!(!description_matches_display_name("3.0", "hidemy.name VPN"));
    }

    #[test]
    fn a_renamed_connection_on_a_stock_driver_still_answers_to_its_saved_name() {
        // The Windows 11 case: hidemy.name renames the CONNECTION but ships the
        // stock TAP driver, so the saved name shares no token with the driver
        // description and only the friendly name can identify the adapter.
        let mut vpn = adapter("tap", 9, true, true, Some([10, 88, 0, 1]));
        vpn.description = "TAP-Windows Adapter V9".into();
        vpn.friendly_name = "hidemy.name VPN OpenVPN Adapter".into();

        assert!(!description_matches_display_name(
            &vpn.description,
            "hidemy.name VPN OpenVPN Adapter"
        ));
        assert!(adapter_answers_to_saved_name(
            &vpn,
            "hidemy.name VPN OpenVPN Adapter"
        ));
        // The stored name follows the connection, so the GUI keeps the label
        // the user recognises.
        assert_eq!(
            preferred_display_name(&vpn),
            "hidemy.name VPN OpenVPN Adapter"
        );

        // An unrelated adapter must not be adopted through either name.
        let mut wifi = adapter("wifi", 17, true, true, Some([192, 168, 0, 1]));
        wifi.description = "Intel(R) Dual Band Wireless-AC 7265".into();
        wifi.friendly_name = "Wi-Fi".into();
        assert!(!adapter_answers_to_saved_name(
            &wifi,
            "hidemy.name VPN OpenVPN Adapter"
        ));
    }

    #[test]
    fn a_blank_friendly_name_falls_back_to_the_driver_description() {
        let mut vpn = adapter("tap", 9, true, true, Some([10, 88, 0, 1]));
        vpn.description = "TAP-Windows Adapter V9".into();
        vpn.friendly_name = "   ".into();
        assert_eq!(preferred_display_name(&vpn), "TAP-Windows Adapter V9");
        assert!(adapter_answers_to_saved_name(
            &vpn,
            "TAP-Windows Adapter V9"
        ));
    }

    #[test]
    fn recompute_active_resolves_target_and_routes_for_the_active_user() {
        // End-to-end through the wiring entry point: active SID → its
        // secondary binding → live adapter → target → routes.
        let api = Arc::new(MockWindowsApi::new());
        let sec = adapter("vpn", 9, true, true, Some([10, 0, 0, 1]));
        let sec_id = sec.stable_id();
        api.set_adapter_infos(vec![sec.clone()]);

        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
        );
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary("S-IVANOV", &sec_id);

        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);
        let delta = coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
        assert_eq!(delta.added, 1);
        let table = api.get_ip_forward_table().unwrap();
        let r = table
            .iter()
            .find(|r| r.destination == Ipv4Addr::new(1, 1, 1, 1))
            .unwrap();
        assert_eq!(r.interface_index, 9);
        assert_eq!(r.next_hop, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn adopt_orphans_picks_our_signature_then_recompute_purges_unwanted() {
        // Two of our /32 @metric5 orphans + one foreign route survive a
        // crash. Adoption claims only the two; a recompute that desires just
        // .1 deletes .2 but leaves the foreign route untouched.
        let api = Arc::new(MockWindowsApi::new());
        let ours_a = RouteEntry {
            destination: Ipv4Addr::new(1, 1, 1, 1),
            prefix_length: 32,
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
            interface_index: 9,
            metric: 5,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        };
        let ours_b = RouteEntry {
            destination: Ipv4Addr::new(2, 2, 2, 2),
            ..ours_a.clone()
        };
        // Foreign: a /24 at a different metric — must NOT be adopted.
        let foreign = RouteEntry {
            destination: Ipv4Addr::new(8, 8, 8, 0),
            prefix_length: 24,
            next_hop: Ipv4Addr::new(192, 168, 0, 1),
            interface_index: 3,
            metric: 256,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        };
        api.set_route_table(vec![ours_a.clone(), ours_b, foreign.clone()]);

        let sec = adapter("vpn", 9, true, true, Some([10, 0, 0, 1]));
        let sec_id = sec.stable_id();
        api.set_adapter_infos(vec![sec]);
        let rules = Arc::new(FakeRules::new());
        rules.set_secondary(
            "S-IVANOV",
            CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
        );
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary("S-IVANOV", &sec_id);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

        coord.adopt_orphans_from_table();
        assert_eq!(coord.owned_count(), 2, "both /32 @5 orphans adopted");

        // Active user wants only .1 → .2 is purged, foreign stays.
        coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
        let dests = table_dests(&api);
        assert!(
            dests.contains(&Ipv4Addr::new(1, 1, 1, 1)),
            "desired route kept"
        );
        assert!(!dests.contains(&Ipv4Addr::new(2, 2, 2, 2)), "orphan purged");
        assert!(
            dests.contains(&Ipv4Addr::new(8, 8, 8, 0)),
            "foreign route untouched"
        );
    }

    #[test]
    fn adopt_orphans_claims_mode_a_counter_overlay_not_just_slash32() {
        // Regression (block 16, : a crash/kill (not a graceful stop)
        // can strand the mode-A `/2` counter-overlay (metric 5, on the primary
        // NIC) in the OS table. Adoption must claim it alongside the `/32`
        // host routes — previously only `/32` was adopted, so the `/2` lingered
        // forever and could keep forcing all non-rule traffic to the primary
        // after the owning service was gone (the kill-during-rebuild leftover).
        let api = Arc::new(MockWindowsApi::new());
        // Our /2 counter-overlay half @metric5 (primary NIC ifindex 12).
        let overlay = RouteEntry {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            prefix_length: 2,
            next_hop: Ipv4Addr::new(192, 168, 0, 1),
            interface_index: 12,
            metric: 5,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        };
        // Our /32 secondary host route @metric5.
        let host = RouteEntry {
            destination: Ipv4Addr::new(1, 1, 1, 1),
            prefix_length: 32,
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
            interface_index: 9,
            metric: 5,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        };
        // Foreign /2 at a different metric — must NOT be adopted.
        let foreign_overlay = RouteEntry {
            destination: Ipv4Addr::new(64, 0, 0, 0),
            prefix_length: 2,
            next_hop: Ipv4Addr::new(192, 168, 0, 1),
            interface_index: 12,
            metric: 256,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        };
        api.set_route_table(vec![overlay, host, foreign_overlay]);

        let rules = Arc::new(FakeRules::new());
        let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

        coord.adopt_orphans_from_table();
        assert_eq!(
            coord.owned_count(),
            2,
            "the /2 counter-overlay and the /32 host route are both adopted; the foreign /2 @256 is not"
        );
    }

    #[test]
    fn recompute_active_with_no_active_user_clears_table() {
        let api = Arc::new(MockWindowsApi::new());
        let rules = Arc::new(FakeRules::new());
        let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
        let delta = coord.recompute_active(&[]).unwrap();
        assert!(delta.is_noop());
        assert!(table_dests(&api).is_empty());
    }

    #[test]
    fn principal_with_no_rules_clears_routes_via_read_through_miss() {
        let api = Arc::new(MockWindowsApi::new());
        let rules = Arc::new(FakeRules::new()); // nothing set, no baseline
        let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
        let delta = coord
            .recompute_for("S-UNKNOWN", &res(Some(target())))
            .unwrap();
        assert!(delta.is_noop());
        assert!(table_dests(&api).is_empty());
    }
}

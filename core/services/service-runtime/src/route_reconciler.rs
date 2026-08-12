//! secondary-route reconciler.
//!
//! Brings the system route table into line with a desired owned route set
//! (produced by [`crate::route_codegen`]). It tracks the routes it has
//! applied and, on each [`SecondaryRouteReconciler::reconcile`], diffs the
//! new desired set against them: it **deletes** owned routes that are no
//! longer desired and **adds** newly-desired ones, in a single
//! [`RoutingTransaction`] that rolls back on partial failure.
//!
//! ## Single-active-user model (Free)
//!
//! The Windows route table is **machine-wide** — a route entry has no user
//! dimension. So the table reflects exactly one user's routing at a time:
//! the active console-session user (block 16.18 wiring). When the active
//! user changes, the wiring recomputes the desired set for the new user
//! and calls `reconcile`, which tears down the previous user's routes and
//! installs the new user's. Per-SID WFP filters (the kill-switch) remain
//! per-user and simultaneous; only the route table is single-owner.
//! Simultaneous distinct routing for multiple concurrently-active sessions
//! needs a kernel callout driver and is a Pro feature (`strategy.rs`).
//!
//! ## Ownership tracking
//!
//! The OS never reports `is_ours` (the FFI stamps `false`), so the
//! reconciler is the source of truth for which routes it owns, tracked
//! in-memory. Cleanup of routes orphaned by a crash (present in the OS
//! table but not in memory) is handled at startup by the wiring layer,
//! which knows the secondary gateway/metric signature — kept out of this
//! pure diff/apply core.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use nrr_platform_api::routing::RoutingTransaction;
use nrr_platform_api::{PlatformError, RouteEntry, RoutingAction, WindowsApiPort};

use crate::route_codegen::{OVERLAY_HIGH, OVERLAY_LOW};

/// Identity of a route for diffing — everything but `metric`/`is_ours`.
/// Two routes with the same key are "the same route"; a metric-only change
/// is not a meaningful diff for our `/32` host routes.
type RouteKey = (Ipv4Addr, u8, Ipv4Addr, u32);

fn route_key(r: &RouteEntry) -> RouteKey {
    (
        r.destination,
        r.prefix_length,
        r.next_hop,
        r.interface_index,
    )
}

/// What a route currently in the system table represents, from the
/// route-ownership coordinator's perspective (block 16.18.vpn).
///
/// NetRuleRouter takes ownership of the IPv4 route table over a
/// redirect-gateway VPN: it may strip the VPN client's self-installed
/// split-default overlay (so mode A's non-rule traffic falls back to the
/// primary default, and mode B installs *our* overlay instead), but it must
/// NEVER remove the bootstrap host route to the VPN server — doing so kills
/// the tunnel. This classification is the safety gate for that stripping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOwnership {
    /// We installed it (`is_ours`). Reconciled against the desired set; never
    /// treated as foreign.
    Ours,
    /// A split-default half (`0.0.0.0/1` / `128.0.0.0/1`) the VPN client
    /// installed on the secondary interface (`redirect-gateway`). Strippable
    /// when NetRuleRouter owns the table.
    VpnRedirectOverlay,
    /// The bootstrap host route to the VPN server itself — a `/32` reached via
    /// the *primary* gateway, so the encrypted tunnel packets egress the real
    /// link rather than the tunnel. Removing it tears down the VPN. NEVER strip.
    BootstrapHostRoute,
    /// Anything else (the OS default `0.0.0.0/0`, on-link routes, unrelated
    /// entries). Not ours and not the VPN's redirect/bootstrap — leave it.
    Untracked,
}

/// Classify one route for ownership-based stripping (block 16.18.vpn).
///
/// `secondary_ifindex` is the VPN interface; `primary_gateway` is the real
/// (Ethernet) next-hop, used to recognise — and protect — the bootstrap host
/// route. Pure; no I/O. Only [`RouteOwnership::VpnRedirectOverlay`] is safe to
/// strip; every other variant must be left in place.
pub fn classify_route_ownership(
    route: &RouteEntry,
    secondary_ifindex: u32,
    primary_gateway: Option<Ipv4Addr>,
) -> RouteOwnership {
    if route.is_ours {
        return RouteOwnership::Ours;
    }
    // Bootstrap host route FIRST so it can never be mistaken for anything
    // strippable: a /32 reached via the primary gateway. Checked regardless of
    // interface — defence in depth, even if a client installs it unusually.
    if route.prefix_length == 32 {
        if let Some(pg) = primary_gateway {
            if route.next_hop == pg {
                return RouteOwnership::BootstrapHostRoute;
            }
        }
    }
    // The VPN's redirect-gateway split halves on the secondary interface.
    if route.interface_index == secondary_ifindex && is_split_default_half(route) {
        return RouteOwnership::VpnRedirectOverlay;
    }
    RouteOwnership::Untracked
}

fn is_split_default_half(route: &RouteEntry) -> bool {
    (route.destination == OVERLAY_LOW.0 && route.prefix_length == OVERLAY_LOW.1)
        || (route.destination == OVERLAY_HIGH.0 && route.prefix_length == OVERLAY_HIGH.1)
}

/// the VPN **server** IPs the
/// kill-switch must never block, so the tunnel can (re)establish.
///
/// These are the destinations of the bootstrap host-routes: a `/32` reached
/// via the primary gateway (see [`classify_route_ownership`]). The VPN client
/// installs one per server endpoint so its own encrypted traffic reaches the
/// server over the real interface, *outside* the tunnel. Deduplicated, order
/// preserved. Empty when there is no primary gateway or no such route — the
/// caller then refuses to arm the catch-all (fail-open), since blocking the
/// server would deadlock reconnection.
pub fn bootstrap_server_ips(
    routes: &[RouteEntry],
    secondary_ifindex: u32,
    primary_gateway: Option<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let mut seen = HashSet::new();
    routes
        .iter()
        .filter(|r| {
            matches!(
                classify_route_ownership(r, secondary_ifindex, primary_gateway),
                RouteOwnership::BootstrapHostRoute
            )
        })
        .map(|r| r.destination)
        .filter(|ip| seen.insert(*ip))
        .collect()
}

/// the primary interface's
/// directly-connected IPv4 subnets, as `(network, prefix_len)`.
///
/// Derived from the on-link connected routes on `primary_ifindex` (next-hop
/// `0.0.0.0`, prefix `1..=31` — skips the default route and host routes). The
/// catch-all kill-switch permits these so DHCP renewal, the local
/// router/DNS, and LAN devices keep working while everything else off-tunnel
/// is blocked. Deduplicated, order preserved.
pub fn primary_local_subnets(routes: &[RouteEntry], primary_ifindex: u32) -> Vec<(Ipv4Addr, u8)> {
    let mut seen = HashSet::new();
    routes
        .iter()
        .filter(|r| {
            r.interface_index == primary_ifindex
                && r.next_hop.is_unspecified()
                && (1..=31).contains(&r.prefix_length)
        })
        .map(|r| (r.destination, r.prefix_length))
        .filter(|s| seen.insert(*s))
        .collect()
}

/// What a single `reconcile` changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RouteReconcileDelta {
    pub added: usize,
    pub removed: usize,
}

impl RouteReconcileDelta {
    pub fn is_noop(&self) -> bool {
        self.added == 0 && self.removed == 0
    }
}

/// Reconciles the owned secondary-route set into the system route table.
pub struct SecondaryRouteReconciler {
    api: Arc<dyn WindowsApiPort>,
    /// Routes this reconciler currently owns (last successfully applied
    /// desired set).
    owned: Mutex<Vec<RouteEntry>>,
}

// `owned` is a `Mutex`; `lock().unwrap_or_else(into_inner)` recovers from a
// poisoned lock instead of unwrapping (workspace denies `unwrap_used`).
impl SecondaryRouteReconciler {
    pub fn new(api: Arc<dyn WindowsApiPort>) -> Self {
        Self {
            api,
            owned: Mutex::new(Vec::new()),
        }
    }

    /// Seed the owned set without touching the route table. Used by the
    /// wiring layer's startup orphan-adoption (routes already present in
    /// the OS table that match our signature) so the next `reconcile`
    /// can delete the ones the new desired set no longer wants.
    pub fn adopt_owned(&self, routes: Vec<RouteEntry>) {
        let mut owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        *owned = routes;
    }

    /// Number of routes currently owned.
    pub fn owned_count(&self) -> usize {
        self.owned.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Diff `desired` against the owned set and apply the difference. On
    /// success the owned set becomes exactly `desired`. On any platform
    /// error the partial changes are rolled back and the owned set is left
    /// unchanged.
    pub fn reconcile(&self, desired: &[RouteEntry]) -> Result<RouteReconcileDelta, PlatformError> {
        let mut owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());

        let desired_keys: HashSet<RouteKey> = desired.iter().map(route_key).collect();
        let owned_keys: HashSet<RouteKey> = owned.iter().map(route_key).collect();

        let mut actions: Vec<RoutingAction> = Vec::new();
        // Delete owned routes the new desired set drops.
        let mut removed = 0usize;
        for r in owned.iter() {
            if !desired_keys.contains(&route_key(r)) {
                actions.push(RoutingAction::DeleteRoute(r.clone()));
                removed += 1;
            }
        }
        // Add newly-desired routes (AddRoute is idempotent on conflict, so
        // a route already in the table is harmless).
        let mut added = 0usize;
        for r in desired.iter() {
            if !owned_keys.contains(&route_key(r)) {
                actions.push(RoutingAction::AddRoute(r.clone()));
                added += 1;
            }
        }

        if actions.is_empty() {
            return Ok(RouteReconcileDelta::default());
        }

        let mut tx = RoutingTransaction::new(Arc::clone(&self.api));
        match tx.execute(&actions) {
            Ok(()) => {
                tx.finalize();
                *owned = desired.to_vec();
                Ok(RouteReconcileDelta { added, removed })
            }
            Err(e) => {
                // Best-effort undo of the actions that landed before the
                // failure; leave `owned` untouched so the next reconcile
                // retries the full diff.
                let _ = tx.rollback();
                Err(e)
            }
        }
    }

    /// Tear down every owned route (active user logged off / service
    /// stopping). Equivalent to `reconcile(&[])`.
    pub fn clear(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconcile(&[])
    }

    /// graceful-stop "keep secondary" teardown: delete NRR's
    /// overlays (the mode-A `/2` counter-overlays and the mode-B `/1`
    /// split-default) but KEEP the secondary `/32` host routes, so rule-matched
    /// hosts keep egressing the secondary adapter after the service stops while general
    /// traffic returns to whatever the OS/VPN provides — the primary default
    /// for a gateway-less VPN, the VPN's own redirect for a full-tunnel one. No
    /// fabricated default, so a split / corp VPN is respected (its non-org
    /// traffic is not forced through the tunnel). Equivalent to
    /// `reconcile(owned.filter(|r| r.prefix_length == 32))`.
    pub fn retain_secondary_hosts(&self) -> Result<RouteReconcileDelta, PlatformError> {
        let keep: Vec<RouteEntry> = {
            let owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
            owned
                .iter()
                .filter(|r| r.prefix_length == 32)
                .cloned()
                .collect()
        };
        self.reconcile(&keep)
    }

    /// strip the VPN client's own
    /// redirect-gateway overlay (the `/1` split-default pair it installed on
    /// the secondary interface) so NetRuleRouter's policy — not the VPN
    /// client — decides what rides the tunnel.
    ///
    /// **DORMANT — not wired into `recompute_for`.** Hardware testing showed
    /// removing a live VPN client's routes destabilises it (hidemy.name's
    /// OpenVPN forced reconnects). Kept for reference / a possible future
    /// event-driven owner; the live mode-A selectivity path will instead use a
    /// `/2` counter-overlay via primary (additive, no removal). Do NOT re-wire
    /// this without solving the client-disruption problem.
    ///
    /// In **mode A** the active user owns no `/1`, so the VPN's pair is removed
    /// and non-rule traffic falls back to the primary default (selective). In
    /// **mode B** the active user owns a `/1` overlay with the *same key* (our
    /// next-hop is the tunnel peer the VPN itself uses), so the owned-set guard
    /// keeps it — the redirect pair is preserved and our exceptions win by
    /// longest-prefix match.
    ///
    /// Safety: only routes classified [`RouteOwnership::VpnRedirectOverlay`]
    /// are removed, AND never a route whose key we currently own (the live OS
    /// table reports `is_ours = false` for everything, so we exclude our own
    /// routes by key, not by the flag). The bootstrap host route and the OS
    /// default are never classified as strippable. Best-effort and idempotent:
    /// returns how many foreign overlay routes were removed (0 when there is
    /// nothing to strip). A delete failure rolls back this strip transaction
    /// and surfaces the error to the caller (who logs it; routing already
    /// applied).
    pub fn strip_foreign_overlay(
        &self,
        secondary_ifindex: u32,
        primary_gateway: Option<Ipv4Addr>,
    ) -> Result<usize, PlatformError> {
        let owned_keys: HashSet<RouteKey> = {
            let owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
            owned.iter().map(route_key).collect()
        };
        let table = self.api.get_ip_forward_table()?;
        let foreign: Vec<RouteEntry> = table
            .into_iter()
            .filter(|r| {
                !owned_keys.contains(&route_key(r))
                    && classify_route_ownership(r, secondary_ifindex, primary_gateway)
                        == RouteOwnership::VpnRedirectOverlay
            })
            .collect();
        if foreign.is_empty() {
            return Ok(0);
        }
        let actions: Vec<RoutingAction> = foreign
            .iter()
            .cloned()
            .map(RoutingAction::DeleteRoute)
            .collect();
        let mut tx = RoutingTransaction::new(Arc::clone(&self.api));
        match tx.execute(&actions) {
            Ok(()) => {
                tx.finalize();
                Ok(foreign.len())
            }
            Err(e) => {
                let _ = tx.rollback();
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::MockWindowsApi;

    fn route(d: [u8; 4], gw: [u8; 4], ifx: u32) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(d),
            prefix_length: 32,
            next_hop: Ipv4Addr::from(gw),
            interface_index: ifx,
            metric: 5,
            is_ours: true,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    fn table_dests(api: &MockWindowsApi) -> HashSet<Ipv4Addr> {
        api.get_ip_forward_table()
            .unwrap()
            .iter()
            .map(|r| r.destination)
            .collect()
    }

    #[test]
    fn first_reconcile_adds_all_desired() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        let desired = vec![
            route([1, 1, 1, 1], [10, 0, 0, 1], 7),
            route([2, 2, 2, 2], [10, 0, 0, 1], 7),
        ];
        let delta = rec.reconcile(&desired).unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 2,
                removed: 0
            }
        );
        assert_eq!(rec.owned_count(), 2);
        assert_eq!(
            table_dests(&api),
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)])
        );
    }

    #[test]
    fn reconcile_is_idempotent_when_desired_unchanged() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        let desired = vec![route([1, 1, 1, 1], [10, 0, 0, 1], 7)];
        rec.reconcile(&desired).unwrap();
        let delta = rec.reconcile(&desired).unwrap();
        assert!(delta.is_noop());
        assert_eq!(table_dests(&api).len(), 1);
    }

    #[test]
    fn reconcile_adds_new_and_removes_dropped() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        rec.reconcile(&[
            route([1, 1, 1, 1], [10, 0, 0, 1], 7),
            route([2, 2, 2, 2], [10, 0, 0, 1], 7),
        ])
        .unwrap();
        // New desired: drop .2, keep .1, add .3.
        let delta = rec
            .reconcile(&[
                route([1, 1, 1, 1], [10, 0, 0, 1], 7),
                route([3, 3, 3, 3], [10, 0, 0, 1], 7),
            ])
            .unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 1,
                removed: 1
            }
        );
        assert_eq!(
            table_dests(&api),
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(3, 3, 3, 3)])
        );
    }

    #[test]
    fn changing_secondary_gateway_replaces_the_route() {
        // Same destination, different gateway/ifindex → delete old + add new.
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        rec.reconcile(&[route([1, 1, 1, 1], [10, 0, 0, 1], 7)])
            .unwrap();
        let delta = rec
            .reconcile(&[route([1, 1, 1, 1], [192, 168, 0, 1], 9)])
            .unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 1,
                removed: 1
            }
        );
        let table = api.get_ip_forward_table().unwrap();
        let r = table
            .iter()
            .find(|r| r.destination == Ipv4Addr::new(1, 1, 1, 1))
            .unwrap();
        assert_eq!(r.next_hop, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(r.interface_index, 9);
    }

    #[test]
    fn clear_removes_all_owned_routes() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        rec.reconcile(&[
            route([1, 1, 1, 1], [10, 0, 0, 1], 7),
            route([2, 2, 2, 2], [10, 0, 0, 1], 7),
        ])
        .unwrap();
        let delta = rec.clear().unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 0,
                removed: 2
            }
        );
        assert!(table_dests(&api).is_empty());
        assert_eq!(rec.owned_count(), 0);
    }

    #[test]
    fn adopt_owned_lets_next_reconcile_purge_orphans() {
        // Simulate a crash: routes exist in the table + we adopt them as
        // owned; a fresh desired set then drops one.
        let api = Arc::new(MockWindowsApi::new());
        let orphan_a = route([1, 1, 1, 1], [10, 0, 0, 1], 7);
        let orphan_b = route([2, 2, 2, 2], [10, 0, 0, 1], 7);
        api.set_route_table(vec![orphan_a.clone(), orphan_b.clone()]);
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        rec.adopt_owned(vec![orphan_a.clone(), orphan_b]);
        // New desired keeps only .1 → .2 must be purged.
        let delta = rec.reconcile(&[orphan_a]).unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 0,
                removed: 1
            }
        );
        assert_eq!(
            table_dests(&api),
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1)])
        );
    }

    // ── route ownership classification (block 16.18.vpn, slice B) ──

    fn raw_route(d: [u8; 4], prefix: u8, gw: [u8; 4], ifx: u32, ours: bool) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(d),
            prefix_length: prefix,
            next_hop: Ipv4Addr::from(gw),
            interface_index: ifx,
            metric: 5,
            is_ours: ours,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    // ── Kill-switch exemptions (block 16.18.vpn D3) ─────────────────────────

    #[test]
    fn bootstrap_server_ips_collects_host_routes_via_primary_gateway() {
        let pg = [192, 168, 1, 1];
        let routes = vec![
            raw_route([203, 0, 113, 7], 32, pg, 12, false), // VPN server #1 (bootstrap)
            raw_route([198, 51, 100, 9], 32, pg, 12, false), // VPN server #2 (bootstrap)
            raw_route([203, 0, 113, 7], 32, pg, 12, false), // dup → deduped
            raw_route([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, false), // VPN redirect half (not a server)
            raw_route([93, 184, 216, 34], 32, [10, 91, 192, 1], 78, true), // our /32 (is_ours)
        ];
        let got = bootstrap_server_ips(&routes, 78, Some(Ipv4Addr::from(pg)));
        assert_eq!(
            got,
            vec![
                Ipv4Addr::new(203, 0, 113, 7),
                Ipv4Addr::new(198, 51, 100, 9)
            ]
        );
    }

    #[test]
    fn bootstrap_server_ips_empty_without_primary_gateway() {
        // No primary gateway → the bootstrap classifier can't fire → empty,
        // which makes the caller refuse to arm the catch-all (fail-open).
        let routes = vec![raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, false)];
        assert!(bootstrap_server_ips(&routes, 78, None).is_empty());
    }

    #[test]
    fn primary_local_subnets_collects_on_link_connected_routes_only() {
        let routes = vec![
            raw_route([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, false), // connected /24 → yes
            raw_route([10, 0, 0, 0], 8, [0, 0, 0, 0], 12, false),     // connected /8 → yes
            raw_route([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, false),  // default → no
            raw_route([192, 168, 1, 50], 32, [0, 0, 0, 0], 12, false), // host /32 → no
            raw_route([172, 16, 0, 0], 12, [0, 0, 0, 0], 99, false),  // other ifindex → no
        ];
        let got = primary_local_subnets(&routes, 12);
        assert_eq!(
            got,
            vec![
                (Ipv4Addr::new(192, 168, 1, 0), 24),
                (Ipv4Addr::new(10, 0, 0, 0), 8)
            ]
        );
    }

    #[test]
    fn classify_our_own_overlay_is_ours_not_foreign() {
        // Our mode-B overlay (is_ours) must classify as Ours even though it has
        // the same /1 shape as the VPN's redirect pair — so we never strip it.
        let r = raw_route([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, true);
        assert_eq!(
            classify_route_ownership(&r, 78, Some(Ipv4Addr::new(192, 168, 1, 1))),
            RouteOwnership::Ours
        );
    }

    #[test]
    fn classify_vpn_redirect_pair_on_secondary() {
        let pg = Some(Ipv4Addr::new(192, 168, 1, 1));
        let lo = raw_route([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, false);
        let hi = raw_route([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, false);
        assert_eq!(
            classify_route_ownership(&lo, 78, pg),
            RouteOwnership::VpnRedirectOverlay
        );
        assert_eq!(
            classify_route_ownership(&hi, 78, pg),
            RouteOwnership::VpnRedirectOverlay
        );
    }

    #[test]
    fn classify_split_half_on_other_interface_is_untracked() {
        // A /1 on some other interface is not our VPN's redirect — don't touch.
        let r = raw_route([0, 0, 0, 0], 1, [10, 0, 0, 1], 12, false);
        assert_eq!(
            classify_route_ownership(&r, 78, Some(Ipv4Addr::new(192, 168, 1, 1))),
            RouteOwnership::Untracked
        );
    }

    #[test]
    fn classify_bootstrap_host_route_via_primary_gateway_is_preserved() {
        // /32 to the VPN server via the Ethernet gateway → never strip.
        let pg = Ipv4Addr::new(192, 168, 1, 1);
        let boot = raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, false);
        assert_eq!(
            classify_route_ownership(&boot, 78, Some(pg)),
            RouteOwnership::BootstrapHostRoute
        );
        // Defence in depth: even if it appeared on the secondary ifindex.
        let boot_on_sec = raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 78, false);
        assert_eq!(
            classify_route_ownership(&boot_on_sec, 78, Some(pg)),
            RouteOwnership::BootstrapHostRoute
        );
    }

    #[test]
    fn classify_os_default_and_unrelated_are_untracked() {
        let pg = Some(Ipv4Addr::new(192, 168, 1, 1));
        // OS default /0 (prefix 0, not 1) — never strippable.
        let def = raw_route([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, false);
        assert_eq!(
            classify_route_ownership(&def, 78, pg),
            RouteOwnership::Untracked
        );
        // Unrelated /24 on the secondary interface.
        let other = raw_route([10, 0, 0, 0], 24, [10, 0, 0, 1], 78, false);
        assert_eq!(
            classify_route_ownership(&other, 78, pg),
            RouteOwnership::Untracked
        );
    }

    #[test]
    fn classify_without_primary_gateway_leaves_host_route_untracked() {
        // Without a known primary gateway we cannot identify the bootstrap, so
        // a /32 falls through to Untracked — safe, since stripping only ever
        // targets VpnRedirectOverlay (/1 on the secondary), never /32s.
        let r = raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, false);
        assert_eq!(
            classify_route_ownership(&r, 78, None),
            RouteOwnership::Untracked
        );
    }

    // ── strip_foreign_overlay (block 16.18.vpn, slice C2) ──

    #[test]
    fn strip_removes_vpn_redirect_pair_keeps_bootstrap_owned_and_default() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        // Mode A: we own a /32 secondary route (its key goes into `owned`).
        rec.reconcile(&[route([5, 5, 5, 5], [10, 91, 192, 1], 78)])
            .unwrap();
        // The live OS table (FFI reports is_ours=false for ALL): our /32 + the
        // VPN's redirect /1 pair on the secondary + the bootstrap /32 via the
        // primary gateway + the OS default.
        api.set_route_table(vec![
            raw_route([5, 5, 5, 5], 32, [10, 91, 192, 1], 78, false), // ours (key owned)
            raw_route([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, false),  // VPN redirect lo
            raw_route([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, false), // VPN redirect hi
            raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, false), // bootstrap
            raw_route([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, false),  // OS default
        ]);
        let n = rec
            .strip_foreign_overlay(78, Some(Ipv4Addr::new(192, 168, 1, 1)))
            .unwrap();
        assert_eq!(n, 2, "only the two /1 redirect halves are stripped");
        let table = api.get_ip_forward_table().unwrap();
        assert!(
            !table.iter().any(|r| r.prefix_length == 1),
            "VPN redirect pair removed"
        );
        assert!(
            table
                .iter()
                .any(|r| r.destination == Ipv4Addr::new(203, 0, 113, 7)),
            "bootstrap host route preserved (tunnel survives)"
        );
        assert!(
            table
                .iter()
                .any(|r| r.destination == Ipv4Addr::new(5, 5, 5, 5)),
            "our owned /32 preserved"
        );
        assert!(
            table.iter().any(|r| r.prefix_length == 0),
            "OS default preserved (fail-safe anchor)"
        );
    }

    #[test]
    fn strip_skips_redirect_overlay_we_own_in_mode_b() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        // Mode B: we own the /1 overlay (same key as the VPN's redirect pair —
        // our next-hop is the tunnel peer the VPN itself uses).
        let overlay_lo = RouteEntry {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            prefix_length: 1,
            next_hop: Ipv4Addr::new(10, 91, 192, 1),
            interface_index: 78,
            metric: 5,
            is_ours: true,
            table: nrr_platform_api::RouteTableRef::Main,
        };
        let overlay_hi = RouteEntry {
            destination: Ipv4Addr::new(128, 0, 0, 0),
            ..overlay_lo.clone()
        };
        rec.reconcile(&[overlay_lo, overlay_hi]).unwrap();
        // Live table has the /1 pair (is_ours=false from FFI) — same keys we own.
        api.set_route_table(vec![
            raw_route([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, false),
            raw_route([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, false),
        ]);
        let n = rec
            .strip_foreign_overlay(78, Some(Ipv4Addr::new(192, 168, 1, 1)))
            .unwrap();
        assert_eq!(n, 0, "we own those /1 keys in mode B → not stripped");
        assert_eq!(api.get_ip_forward_table().unwrap().len(), 2);
    }

    #[test]
    fn retain_secondary_hosts_keeps_slash32_drops_overlays() {
        // graceful stop keeps the /32 rule-routes and
        // drops NRR's /2 counter-overlay and /1 split-default, so rule-matched
        // hosts keep egressing the secondary adapter while general traffic returns to the OS
        // default.
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        let host_a = route([8, 8, 8, 8], [10, 0, 0, 1], 14);
        let host_b = route([1, 1, 1, 1], [10, 0, 0, 1], 14);
        let counter_overlay = raw_route([64, 0, 0, 0], 2, [192, 168, 0, 1], 16, true);
        let split_default = raw_route([0, 0, 0, 0], 1, [10, 0, 0, 1], 14, true);
        rec.reconcile(&[host_a, host_b, counter_overlay, split_default])
            .unwrap();
        assert_eq!(rec.owned_count(), 4);

        let delta = rec.retain_secondary_hosts().unwrap();
        assert_eq!(
            delta.removed, 2,
            "both overlays removed (the /2 and the /1)"
        );
        assert_eq!(delta.added, 0);
        assert_eq!(rec.owned_count(), 2, "only the two /32 host routes remain");
        let dests = table_dests(&api);
        assert!(dests.contains(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(dests.contains(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(
            !dests.contains(&Ipv4Addr::new(64, 0, 0, 0)),
            "counter-overlay gone"
        );
        assert!(
            !dests.contains(&Ipv4Addr::new(0, 0, 0, 0)),
            "split-default gone"
        );
    }
}
